package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// Session item keys; see docs/design.md, section 11.
const (
	userPrefix    = "USER#"
	sessionPrefix = "SESSION#"
	sealPrefix    = "SEAL#"
	changePrefix  = "CHANGE#"
	// guards: a user's session count, a session's reserved changes
	skSessions = "SESSIONS"
	skChanges  = "CHANGES"

	// maxReserveAttempts bounds the tries of a ReserveChange that keeps
	// losing to concurrent seals in the same session.
	maxReserveAttempts = 8
)

// guardItem makes a cap hold under concurrent requests. A request that
// checks the cap reads the guard first and writes it, with whatever it
// adds, only if the version it read is still there; a request that loses
// reads again.
type guardItem struct {
	PK        string `dynamodbav:"pk"`
	SK        string `dynamodbav:"sk"`
	Version   int64  `dynamodbav:"version"`
	ExpiresAt int64  `dynamodbav:"expires_at"`
	// Reserved maps the changes seals hold places for to when each place
	// lapses (epoch milliseconds).
	Reserved map[string]int64 `dynamodbav:"reserved,omitempty"`
}

// guard reads a guard; a missing one is at version 0.
func (d *Dynamo) guard(ctx context.Context, pk, sk string) (guardItem, error) {
	res, err := d.api.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      &d.table,
		Key:            itemKey(pk, sk),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return guardItem{}, err
	}
	var g guardItem
	if len(res.Item) > 0 {
		if err := attributevalue.UnmarshalMap(res.Item, &g); err != nil {
			return guardItem{}, err
		}
	}
	return g, nil
}

// guardCondition conditions a write of a guard on the version read.
func guardCondition(read int64) (string, map[string]string, map[string]types.AttributeValue) {
	if read == 0 {
		return "attribute_not_exists(pk)", nil, nil
	}
	return "#v = :read",
		map[string]string{"#v": "version"},
		map[string]types.AttributeValue{":read": &types.AttributeValueMemberN{Value: strconv.FormatInt(read, 10)}}
}

// sessionItem is a session under its user, one per repository. Its deadline
// (epoch milliseconds) is the idle expiry, for condition expressions.
type sessionItem struct {
	PK        string `dynamodbav:"pk"`
	SK        string `dynamodbav:"sk"`
	Deadline  int64  `dynamodbav:"deadline"`
	ExpiresAt int64  `dynamodbav:"expires_at"`
	Session
}

type sealItem struct {
	PK        string `dynamodbav:"pk"`
	SK        string `dynamodbav:"sk"`
	ExpiresAt int64  `dynamodbav:"expires_at"`
	Seal
}

type changeItem struct {
	PK        string `dynamodbav:"pk"`
	SK        string `dynamodbav:"sk"`
	ExpiresAt int64  `dynamodbav:"expires_at"`
	Change
}

// changeListAttributes is every change attribute but its ciphertexts.
var changeListAttributes = []string{
	"pk", "sk", "session_id", "change_id", "path", "key", "command_id", "agent_id",
	"fingerprint", "regions", "targets", "user_id", "user_login", "sealed_at", "change_expires_at",
}

func itemKey(pk, sk string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		attrPK: &types.AttributeValueMemberS{Value: pk},
		attrSK: &types.AttributeValueMemberS{Value: sk},
	}
}

func userPK(userID int64) string { return userPrefix + strconv.FormatInt(userID, 10) }

func millis(t time.Time) *types.AttributeValueMemberN {
	return &types.AttributeValueMemberN{Value: strconv.FormatInt(t.UnixMilli(), 10)}
}

// Outcomes of one attempt to create a session.
var (
	errSessionExists = errors.New("a live session exists for the repository")
	errGuardMoved    = errors.New("the guard moved on since it was read")
)

func (d *Dynamo) CreateSession(ctx context.Context, s Session, maxSessions int, now time.Time) (Session, bool, error) {
	key := RepoKey(s.Owner, s.Repo)
	item, err := attributevalue.MarshalMap(sessionItem{
		PK:        userPK(s.UserID),
		SK:        sessionPrefix + key,
		Deadline:  s.ExpiresAt.UnixMilli(),
		ExpiresAt: s.ExpiresAt.Unix(),
		Session:   s,
	})
	if err != nil {
		return Session{}, false, fmt.Errorf("failed to encode session %s: %w", s.ID, err)
	}
	// only creating a session moves the guard on, so the cap is reached
	// within maxSessions lost attempts; a few more cover transactions
	// DynamoDB cancels because they ran into each other
	for range maxSessions + 4 {
		// the guard is read before the sessions: a session created after
		// this read moves the guard on, and the write below fails
		g, err := d.guard(ctx, userPK(s.UserID), skSessions)
		if err != nil {
			return Session{}, false, fmt.Errorf("failed to read session count of user %d: %w", s.UserID, err)
		}
		live, err := d.Sessions(ctx, s.UserID, now)
		if err != nil {
			return Session{}, false, err
		}
		for _, existing := range live {
			if RepoKey(existing.Owner, existing.Repo) == key {
				return existing, false, nil
			}
		}
		if len(live) >= maxSessions {
			return Session{}, false, ErrTooManySessions
		}
		err = d.putSession(ctx, s, item, g.Version, now)
		switch {
		case errors.Is(err, errGuardMoved):
			continue
		case errors.Is(err, errSessionExists):
			// created concurrently
			existing, ok, err := d.Session(ctx, s.UserID, key, now)
			if err != nil {
				return Session{}, false, err
			}
			if !ok {
				return Session{}, false, fmt.Errorf("failed to create session for %s: it changed while being created", key)
			}
			return existing, false, nil
		case err != nil:
			return Session{}, false, err
		}
		return s, true, nil
	}
	return Session{}, false, fmt.Errorf("failed to create session for %s: too many sessions created at once", key)
}

// putSession stores a session item and moves the user's session guard on
// from version read, in one transaction.
func (d *Dynamo) putSession(ctx context.Context, s Session, item map[string]types.AttributeValue, read int64, now time.Time) error {
	condition, _, values := guardCondition(read)
	if values == nil {
		values = map[string]types.AttributeValue{}
	}
	values[":next"] = &types.AttributeValueMemberN{Value: strconv.FormatInt(read+1, 10)}
	values[":ttl"] = &types.AttributeValueMemberN{Value: strconv.FormatInt(s.EndsAt.Unix(), 10)}
	_, err := d.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{Put: &types.Put{
				TableName: &d.table,
				Item:      item,
				// an expired session for the repository is replaced, a
				// live one kept
				ConditionExpression:       aws.String("attribute_not_exists(pk) OR " + attrDeadline + " <= :now"),
				ExpressionAttributeValues: map[string]types.AttributeValue{":now": millis(now)},
			}},
			{Update: &types.Update{
				TableName: &d.table,
				Key:       itemKey(userPK(s.UserID), skSessions),
				// the guard lasts as long as the newest session can
				UpdateExpression:          aws.String("SET #v = :next, " + attrExpiresAt + " = :ttl"),
				ConditionExpression:       aws.String(condition),
				ExpressionAttributeNames:  map[string]string{"#v": "version"},
				ExpressionAttributeValues: values,
			}},
		},
	})
	var canceled *types.TransactionCanceledException
	if errors.As(err, &canceled) {
		reason := func(i int) string {
			if i < len(canceled.CancellationReasons) {
				return aws.ToString(canceled.CancellationReasons[i].Code)
			}
			return ""
		}
		switch {
		case reason(0) == "ConditionalCheckFailed":
			return errSessionExists
		case reason(1) == "ConditionalCheckFailed", reason(0) == "TransactionConflict", reason(1) == "TransactionConflict":
			// another session was created meanwhile
			return errGuardMoved
		}
	}
	if err != nil {
		return fmt.Errorf("failed to store session %s: %w", s.ID, err)
	}
	return nil
}

func (d *Dynamo) Session(ctx context.Context, userID int64, repoKey string, now time.Time) (Session, bool, error) {
	res, err := d.api.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      &d.table,
		Key:            itemKey(userPK(userID), sessionPrefix+repoKey),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return Session{}, false, fmt.Errorf("failed to read session for %s: %w", repoKey, err)
	}
	if len(res.Item) == 0 {
		return Session{}, false, nil
	}
	var item sessionItem
	if err := attributevalue.UnmarshalMap(res.Item, &item); err != nil {
		return Session{}, false, fmt.Errorf("failed to decode session for %s: %w", repoKey, err)
	}
	if !item.Live(now) {
		return Session{}, false, nil
	}
	return item.Session, true, nil
}

func (d *Dynamo) Sessions(ctx context.Context, userID int64, now time.Time) ([]Session, error) {
	out := []Session{}
	err := d.query(ctx, userPK(userID), sessionPrefix, nil, func(raw map[string]types.AttributeValue) error {
		var item sessionItem
		if err := attributevalue.UnmarshalMap(raw, &item); err != nil {
			return fmt.Errorf("failed to decode session: %w", err)
		}
		if item.Live(now) {
			out = append(out, item.Session)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to read sessions of user %d: %w", userID, err)
	}
	return out, nil
}

// unlocked is a condition: the session is not locked for a pull request.
const unlocked = "(attribute_not_exists(submit_deadline) OR submit_deadline <= :now)"

func (d *Dynamo) TouchSession(ctx context.Context, userID int64, repoKey, id string, expires, now time.Time) (bool, error) {
	usedAt, err := attributevalue.Marshal(now)
	if err != nil {
		return false, fmt.Errorf("failed to encode session use: %w", err)
	}
	expiresAt, err := attributevalue.Marshal(expires)
	if err != nil {
		return false, fmt.Errorf("failed to encode session expiry: %w", err)
	}
	_, err = d.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: &d.table,
		Key:       itemKey(userPK(userID), sessionPrefix+repoKey),
		UpdateExpression: aws.String("SET used_at = :used, session_expires_at = :expires, " +
			attrDeadline + " = :deadline, " + attrExpiresAt + " = :ttl"),
		ConditionExpression: aws.String("session_id = :id AND " + attrDeadline + " > :now AND " + unlocked),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":used":     usedAt,
			":expires":  expiresAt,
			":deadline": millis(expires),
			":ttl":      &types.AttributeValueMemberN{Value: strconv.FormatInt(expires.Unix(), 10)},
			":id":       &types.AttributeValueMemberS{Value: id},
			":now":      millis(now),
		},
	})
	var failed *types.ConditionalCheckFailedException
	switch {
	case errors.As(err, &failed):
		// gone, or locked
		return false, d.busy(ctx, userID, repoKey, id, now)
	case err != nil:
		return false, fmt.Errorf("failed to update session %s: %w", id, err)
	}
	return true, nil
}

func (d *Dynamo) LockSession(ctx context.Context, userID int64, repoKey, id string, until, now time.Time) (bool, error) {
	_, err := d.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:           &d.table,
		Key:                 itemKey(userPK(userID), sessionPrefix+repoKey),
		UpdateExpression:    aws.String("SET submit_deadline = :until"),
		ConditionExpression: aws.String("session_id = :id AND " + attrDeadline + " > :now AND " + unlocked),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":until": millis(until),
			":id":    &types.AttributeValueMemberS{Value: id},
			":now":   millis(now),
		},
	})
	var failed *types.ConditionalCheckFailedException
	switch {
	case errors.As(err, &failed):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("failed to lock session %s: %w", id, err)
	}
	return true, nil
}

func (d *Dynamo) UnlockSession(ctx context.Context, userID int64, repoKey, id string) error {
	_, err := d.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 &d.table,
		Key:                       itemKey(userPK(userID), sessionPrefix+repoKey),
		UpdateExpression:          aws.String("REMOVE submit_deadline"),
		ConditionExpression:       aws.String("session_id = :id"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":id": &types.AttributeValueMemberS{Value: id}},
	})
	var failed *types.ConditionalCheckFailedException
	if err != nil && !errors.As(err, &failed) {
		return fmt.Errorf("failed to unlock session %s: %w", id, err)
	}
	return nil
}

func (d *Dynamo) DeleteSession(ctx context.Context, userID int64, repoKey, id string) (bool, error) {
	_, err := d.api.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:                 &d.table,
		Key:                       itemKey(userPK(userID), sessionPrefix+repoKey),
		ConditionExpression:       aws.String("session_id = :id"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":id": &types.AttributeValueMemberS{Value: id}},
	})
	var failed *types.ConditionalCheckFailedException
	switch {
	case errors.As(err, &failed):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("failed to delete session %s: %w", id, err)
	}
	return true, nil
}

func (d *Dynamo) DiscardSession(ctx context.Context, userID int64, repoKey, id string, now time.Time) (bool, error) {
	_, err := d.api.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:           &d.table,
		Key:                 itemKey(userPK(userID), sessionPrefix+repoKey),
		ConditionExpression: aws.String("session_id = :id AND " + attrDeadline + " > :now AND " + unlocked),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":id":  &types.AttributeValueMemberS{Value: id},
			":now": millis(now),
		},
	})
	var failed *types.ConditionalCheckFailedException
	switch {
	case errors.As(err, &failed):
		return false, d.busy(ctx, userID, repoKey, id, now)
	case err != nil:
		return false, fmt.Errorf("failed to discard session %s: %w", id, err)
	}
	return true, nil
}

// busy returns ErrSessionBusy when a conditional write on a session failed
// because the session is locked, and nil when it is gone.
func (d *Dynamo) busy(ctx context.Context, userID int64, repoKey, id string, now time.Time) error {
	s, ok, err := d.Session(ctx, userID, repoKey, now)
	if err == nil && ok && s.ID == id && s.Locked(now) {
		err = ErrSessionBusy
	}
	return err
}

func (d *Dynamo) PutSeal(ctx context.Context, s Seal) error {
	item, err := attributevalue.MarshalMap(sealItem{
		PK:        sessionPrefix + s.SessionID,
		SK:        sealPrefix + s.CommandID,
		ExpiresAt: s.ExpiresAt.Unix(),
		Seal:      s,
	})
	if err != nil {
		return fmt.Errorf("failed to encode seal %s: %w", s.CommandID, err)
	}
	_, err = d.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           &d.table,
		Item:                item,
		ConditionExpression: aws.String("attribute_not_exists(pk)"),
	})
	if err != nil {
		return fmt.Errorf("failed to store seal %s: %w", s.CommandID, err)
	}
	return nil
}

func (d *Dynamo) Seal(ctx context.Context, sessionID, commandID string) (Seal, bool, error) {
	res, err := d.api.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      &d.table,
		Key:            itemKey(sessionPrefix+sessionID, sealPrefix+commandID),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return Seal{}, false, fmt.Errorf("failed to read seal %s: %w", commandID, err)
	}
	if len(res.Item) == 0 {
		return Seal{}, false, nil
	}
	var item sealItem
	if err := attributevalue.UnmarshalMap(res.Item, &item); err != nil {
		return Seal{}, false, fmt.Errorf("failed to decode seal %s: %w", commandID, err)
	}
	return item.Seal, true, nil
}

func (d *Dynamo) ReserveChange(ctx context.Context, sessionID, changeID string, existing []string, maxChanges int, until, now time.Time) error {
	pk := sessionPrefix + sessionID
	for range maxReserveAttempts {
		g, err := d.guard(ctx, pk, skChanges)
		if err != nil {
			return fmt.Errorf("failed to read reserved changes of session %s: %w", sessionID, err)
		}
		kept, err := reserveChange(g.Reserved, changeID, existing, maxChanges, until, now)
		if err != nil {
			return err
		}
		lapses := int64(0)
		for _, at := range kept {
			lapses = max(lapses, at)
		}
		item, err := attributevalue.MarshalMap(guardItem{
			PK:      pk,
			SK:      skChanges,
			Version: g.Version + 1,
			// gone once every place has lapsed
			ExpiresAt: time.UnixMilli(lapses).Unix() + 1,
			Reserved:  kept,
		})
		if err != nil {
			return fmt.Errorf("failed to encode reserved changes of session %s: %w", sessionID, err)
		}
		condition, names, values := guardCondition(g.Version)
		_, err = d.api.PutItem(ctx, &dynamodb.PutItemInput{
			TableName:                 &d.table,
			Item:                      item,
			ConditionExpression:       aws.String(condition),
			ExpressionAttributeNames:  names,
			ExpressionAttributeValues: values,
		})
		var moved *types.ConditionalCheckFailedException
		switch {
		case errors.As(err, &moved):
			// another seal in the session reserved first
			continue
		case err != nil:
			return fmt.Errorf("failed to reserve change %s in session %s: %w", changeID, sessionID, err)
		}
		return nil
	}
	return fmt.Errorf("failed to reserve change %s in session %s: too many seals at once", changeID, sessionID)
}

func (d *Dynamo) PutChange(ctx context.Context, c Change) (bool, error) {
	item, err := attributevalue.MarshalMap(changeItem{
		PK:        sessionPrefix + c.SessionID,
		SK:        changePrefix + c.ID,
		ExpiresAt: c.ExpiresAt.Unix(),
		Change:    c,
	})
	if err != nil {
		return false, fmt.Errorf("failed to encode change %s: %w", c.ID, err)
	}
	// command IDs are ULIDs: a newer seal of the same key wins
	_, err = d.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:                 &d.table,
		Item:                      item,
		ConditionExpression:       aws.String("attribute_not_exists(pk) OR command_id <= :cmd"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":cmd": &types.AttributeValueMemberS{Value: c.CommandID}},
	})
	var newer *types.ConditionalCheckFailedException
	switch {
	case errors.As(err, &newer):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("failed to store change %s: %w", c.ID, err)
	}
	return true, nil
}

func (d *Dynamo) Changes(ctx context.Context, sessionID string, ciphertexts bool) ([]Change, error) {
	var projection []string
	if !ciphertexts {
		projection = changeListAttributes
	}
	out := []Change{}
	err := d.query(ctx, sessionPrefix+sessionID, changePrefix, projection, func(raw map[string]types.AttributeValue) error {
		var item changeItem
		if err := attributevalue.UnmarshalMap(raw, &item); err != nil {
			return fmt.Errorf("failed to decode change: %w", err)
		}
		out = append(out, item.Change)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to read changes of session %s: %w", sessionID, err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (d *Dynamo) RemoveChange(ctx context.Context, userID int64, repoKey, sessionID, id string, now time.Time) (bool, error) {
	// one transaction, so a pull request cannot lock the session between
	// the check and the delete
	_, err := d.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{ConditionCheck: &types.ConditionCheck{
				TableName:           &d.table,
				Key:                 itemKey(userPK(userID), sessionPrefix+repoKey),
				ConditionExpression: aws.String("session_id = :id AND " + attrDeadline + " > :now AND " + unlocked),
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":id":  &types.AttributeValueMemberS{Value: sessionID},
					":now": millis(now),
				},
			}},
			{Delete: &types.Delete{
				TableName:           &d.table,
				Key:                 itemKey(sessionPrefix+sessionID, changePrefix+id),
				ConditionExpression: aws.String("attribute_exists(pk)"),
			}},
		},
	})
	var canceled *types.TransactionCanceledException
	switch {
	case errors.As(err, &canceled):
		reasons := canceled.CancellationReasons
		if len(reasons) > 0 && aws.ToString(reasons[0].Code) == "ConditionalCheckFailed" {
			return false, d.busy(ctx, userID, repoKey, sessionID, now)
		}
		if len(reasons) > 1 && aws.ToString(reasons[1].Code) == "ConditionalCheckFailed" {
			return false, nil
		}
		return false, fmt.Errorf("failed to remove change %s: %w", id, err)
	case err != nil:
		return false, fmt.Errorf("failed to remove change %s: %w", id, err)
	}
	return true, nil
}

func (d *Dynamo) PruneChange(ctx context.Context, sessionID, id, commandID string) (bool, error) {
	_, err := d.api.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:                 &d.table,
		Key:                       itemKey(sessionPrefix+sessionID, changePrefix+id),
		ConditionExpression:       aws.String("command_id = :cmd"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":cmd": &types.AttributeValueMemberS{Value: commandID}},
	})
	var failed *types.ConditionalCheckFailedException
	switch {
	case errors.As(err, &failed):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("failed to prune change %s: %w", id, err)
	}
	return true, nil
}

// query reads every item under pk whose sort key starts with prefix,
// optionally projecting only some attributes.
func (d *Dynamo) query(ctx context.Context, pk, prefix string, projection []string, fn func(map[string]types.AttributeValue) error) error {
	in := &dynamodb.QueryInput{
		TableName:              &d.table,
		KeyConditionExpression: aws.String("pk = :pk AND begins_with(sk, :prefix)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk":     &types.AttributeValueMemberS{Value: pk},
			":prefix": &types.AttributeValueMemberS{Value: prefix},
		},
		ConsistentRead: aws.Bool(true),
	}
	if len(projection) > 0 {
		// names such as "path" and "key" are reserved words
		names := map[string]string{}
		refs := make([]string, len(projection))
		for i, attr := range projection {
			ref := "#a" + strconv.Itoa(i)
			names[ref] = attr
			refs[i] = ref
		}
		in.ProjectionExpression = aws.String(strings.Join(refs, ", "))
		in.ExpressionAttributeNames = names
	}
	for {
		res, err := d.api.Query(ctx, in)
		if err != nil {
			return err
		}
		for _, raw := range res.Items {
			if err := fn(raw); err != nil {
				return err
			}
		}
		if len(res.LastEvaluatedKey) == 0 {
			return nil
		}
		in.ExclusiveStartKey = res.LastEvaluatedKey
	}
}
