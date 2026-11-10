package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
)

// Item keys; see docs/design.md, section 11.
const (
	attrPK = "pk"
	attrSK = "sk"

	agentPrefix  = "AGENT#"
	keyPrefix    = "KEY#"
	replayPrefix = "REPLAY#"
	ratePrefix   = "RATE#"
	skState      = "STATE"
	skMeta       = "META"
	skReplay     = "REPLAY"
	skRate       = "RATE"
	skEscrow     = "ESCROW"
	cmdPrefix    = "CMD#"

	// escrowCopyPrefix keys the escrowed copies of a key after the first
	// (skEscrow), one per uploading agent.
	escrowCopyPrefix = skEscrow + "#"
	// revokedPK holds one item per revoked key (revokedPrefix and its
	// fingerprint), so every check-in reads them all with one query.
	revokedPK     = "KEYS"
	revokedPrefix = "REVOKED#"

	// attrExpiresAt is the table's TTL attribute (epoch seconds). TTL only
	// cleans up; code never trusts an item to be gone after it expires.
	attrExpiresAt = "expires_at"
	// attrDeadline is a command's expiry in epoch milliseconds, for
	// condition expressions; the record's own times are RFC 3339 strings.
	attrDeadline = "deadline"

	// batchGetLimit is DynamoDB's BatchGetItem maximum.
	batchGetLimit = 100
)

// DynamoAPI is the subset of the DynamoDB client the store uses.
type DynamoAPI interface {
	PutItem(ctx context.Context, in *dynamodb.PutItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	BatchGetItem(ctx context.Context, in *dynamodb.BatchGetItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.BatchGetItemOutput, error)
	GetItem(ctx context.Context, in *dynamodb.GetItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	UpdateItem(ctx context.Context, in *dynamodb.UpdateItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
	DeleteItem(ctx context.Context, in *dynamodb.DeleteItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
	TransactWriteItems(ctx context.Context, in *dynamodb.TransactWriteItemsInput, opts ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error)
	Query(ctx context.Context, in *dynamodb.QueryInput, opts ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
	CreateTable(ctx context.Context, in *dynamodb.CreateTableInput, opts ...func(*dynamodb.Options)) (*dynamodb.CreateTableOutput, error)
	DescribeTable(ctx context.Context, in *dynamodb.DescribeTableInput, opts ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
}

// Dynamo is the DynamoDB Store: one table, single-table design.
type Dynamo struct {
	api   DynamoAPI
	table string
}

// NewDynamo returns a Store backed by table. It makes no network calls.
func NewDynamo(api DynamoAPI, table string) *Dynamo {
	return &Dynamo{api: api, table: table}
}

type agentItem struct {
	PK string `dynamodbav:"pk"`
	SK string `dynamodbav:"sk"`
	AgentState
}

type keyItem struct {
	PK string `dynamodbav:"pk"`
	SK string `dynamodbav:"sk"`
	KeyRecord
}

func agentKey(id string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		attrPK: &types.AttributeValueMemberS{Value: agentPrefix + id},
		attrSK: &types.AttributeValueMemberS{Value: skState},
	}
}

func (d *Dynamo) PutAgentState(ctx context.Context, s AgentState) error {
	item, err := attributevalue.MarshalMap(agentItem{PK: agentPrefix + s.AgentID, SK: skState, AgentState: s})
	if err != nil {
		return fmt.Errorf("failed to encode state of agent %s: %w", s.AgentID, err)
	}
	if _, err := d.api.PutItem(ctx, &dynamodb.PutItemInput{TableName: &d.table, Item: item}); err != nil {
		return fmt.Errorf("failed to store state of agent %s: %w", s.AgentID, err)
	}
	return nil
}

func (d *Dynamo) GetAgentStates(ctx context.Context, ids []string) (map[string]AgentState, error) {
	keys := make([]map[string]types.AttributeValue, 0, len(ids))
	for _, id := range ids {
		keys = append(keys, agentKey(id))
	}
	out := map[string]AgentState{}
	err := d.batchGet(ctx, keys, "", func(raw map[string]types.AttributeValue) error {
		var item agentItem
		if err := attributevalue.UnmarshalMap(raw, &item); err != nil {
			return fmt.Errorf("failed to decode agent state: %w", err)
		}
		out[item.AgentID] = item.AgentState
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to read agent states: %w", err)
	}
	return out, nil
}

// batchGet reads keys with consistent reads, in batches, retrying
// unprocessed keys, and calls fn for each item found.
func (d *Dynamo) batchGet(ctx context.Context, keys []map[string]types.AttributeValue, projection string, fn func(map[string]types.AttributeValue) error) error {
	for start := 0; start < len(keys); start += batchGetLimit {
		end := min(start+batchGetLimit, len(keys))
		ka := types.KeysAndAttributes{Keys: keys[start:end], ConsistentRead: aws.Bool(true)}
		if projection != "" {
			ka.ProjectionExpression = aws.String(projection)
		}
		request := map[string]types.KeysAndAttributes{d.table: ka}
		for attempt := 0; len(request) > 0; attempt++ {
			if attempt > 0 {
				if attempt > 5 {
					return errors.New("unprocessed keys after retries")
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(time.Duration(attempt*50) * time.Millisecond):
				}
			}
			res, err := d.api.BatchGetItem(ctx, &dynamodb.BatchGetItemInput{RequestItems: request})
			if err != nil {
				return err
			}
			for _, raw := range res.Responses[d.table] {
				if err := fn(raw); err != nil {
					return err
				}
			}
			request = res.UnprocessedKeys
		}
	}
	return nil
}

func (d *Dynamo) PutKeyIfAbsent(ctx context.Context, k KeyRecord) (bool, error) {
	item, err := attributevalue.MarshalMap(keyItem{PK: keyPrefix + k.Fingerprint, SK: skMeta, KeyRecord: k})
	if err != nil {
		return false, fmt.Errorf("failed to encode key %s: %w", k.Fingerprint, err)
	}
	_, err = d.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           &d.table,
		Item:                item,
		ConditionExpression: aws.String("attribute_not_exists(pk)"),
	})
	var exists *types.ConditionalCheckFailedException
	switch {
	case errors.As(err, &exists):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("failed to record key %s: %w", k.Fingerprint, err)
	}
	return true, nil
}

func (d *Dynamo) GetKey(ctx context.Context, fingerprint string) (KeyRecord, bool, error) {
	res, err := d.api.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      &d.table,
		Key:            itemKey(keyPrefix+fingerprint, skMeta),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return KeyRecord{}, false, fmt.Errorf("failed to read key %s: %w", fingerprint, err)
	}
	if len(res.Item) == 0 {
		return KeyRecord{}, false, nil
	}
	var item keyItem
	if err := attributevalue.UnmarshalMap(res.Item, &item); err != nil {
		return KeyRecord{}, false, fmt.Errorf("failed to decode key %s: %w", fingerprint, err)
	}
	return item.KeyRecord, true, nil
}

type revokedItem struct {
	PK string `dynamodbav:"pk"`
	SK string `dynamodbav:"sk"`
	RevokedKey
}

func (d *Dynamo) SetKeyStatus(ctx context.Context, k KeyRecord) (bool, error) {
	at, err := attributevalue.Marshal(k.StatusAt)
	if err != nil {
		return false, fmt.Errorf("failed to encode status time of key %s: %w", k.Fingerprint, err)
	}
	// the key's record and the list of revoked keys change together
	update := types.TransactWriteItem{Update: &types.Update{
		TableName:                &d.table,
		Key:                      itemKey(keyPrefix+k.Fingerprint, skMeta),
		UpdateExpression:         aws.String("SET #status = :status, status_by = :by, status_at = :at"),
		ConditionExpression:      aws.String("attribute_exists(pk)"),
		ExpressionAttributeNames: map[string]string{"#status": "status"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":status": &types.AttributeValueMemberS{Value: k.Status},
			":by":     &types.AttributeValueMemberS{Value: k.StatusBy},
			":at":     at,
		},
	}}
	index := types.TransactWriteItem{Delete: &types.Delete{
		TableName: &d.table,
		Key:       itemKey(revokedPK, revokedPrefix+k.Fingerprint),
	}}
	if k.Status == KeyRevoked {
		item, err := attributevalue.MarshalMap(revokedItem{PK: revokedPK, SK: revokedPrefix + k.Fingerprint, RevokedKey: revokedKey(k)})
		if err != nil {
			return false, fmt.Errorf("failed to encode revoked key %s: %w", k.Fingerprint, err)
		}
		index = types.TransactWriteItem{Put: &types.Put{TableName: &d.table, Item: item}}
	}
	_, err = d.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{update, index},
	})
	switch {
	case conditionFailed(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("failed to set status of key %s: %w", k.Fingerprint, err)
	}
	return true, nil
}

func (d *Dynamo) RevokedKeys(ctx context.Context) (map[string]RevokedKey, error) {
	out := map[string]RevokedKey{}
	in := &dynamodb.QueryInput{
		TableName:              &d.table,
		KeyConditionExpression: aws.String("pk = :pk AND begins_with(sk, :revoked)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk":      &types.AttributeValueMemberS{Value: revokedPK},
			":revoked": &types.AttributeValueMemberS{Value: revokedPrefix},
		},
		ConsistentRead: aws.Bool(true),
	}
	for {
		res, err := d.api.Query(ctx, in)
		if err != nil {
			return nil, fmt.Errorf("failed to read revoked keys: %w", err)
		}
		for _, raw := range res.Items {
			var item revokedItem
			if err := attributevalue.UnmarshalMap(raw, &item); err != nil {
				return nil, fmt.Errorf("failed to decode revoked key: %w", err)
			}
			out[item.Fingerprint] = item.RevokedKey
		}
		if len(res.LastEvaluatedKey) == 0 {
			return out, nil
		}
		in.ExclusiveStartKey = res.LastEvaluatedKey
	}
}

// conditionFailed reports whether a write failed only because a condition
// did not hold, in a single write or in a transaction.
func conditionFailed(err error) bool {
	var failed *types.ConditionalCheckFailedException
	if errors.As(err, &failed) {
		return true
	}
	var canceled *types.TransactionCanceledException
	if !errors.As(err, &canceled) {
		return false
	}
	conditional := false
	for _, r := range canceled.CancellationReasons {
		switch aws.ToString(r.Code) {
		case "ConditionalCheckFailed":
			conditional = true
		case "", "None":
		default:
			return false
		}
	}
	return conditional
}

func (d *Dynamo) PutReplayIfAbsent(ctx context.Context, key string, expires time.Time) (bool, error) {
	_, err := d.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &d.table,
		Item: map[string]types.AttributeValue{
			attrPK:        &types.AttributeValueMemberS{Value: replayPrefix + key},
			attrSK:        &types.AttributeValueMemberS{Value: skReplay},
			attrExpiresAt: &types.AttributeValueMemberN{Value: strconv.FormatInt(expires.Unix(), 10)},
		},
		ConditionExpression: aws.String("attribute_not_exists(pk)"),
	})
	var exists *types.ConditionalCheckFailedException
	switch {
	case errors.As(err, &exists):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("failed to record one-time key: %w", err)
	}
	return true, nil
}

func (d *Dynamo) CountRequest(ctx context.Context, key string, limit int, windowEnd time.Time) (bool, error) {
	end := strconv.FormatInt(windowEnd.Unix(), 10)
	// one item per window; "count" is a reserved word
	_, err := d.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                &d.table,
		Key:                      itemKey(ratePrefix+key+"#"+end, skRate),
		UpdateExpression:         aws.String("ADD #n :one SET " + attrExpiresAt + " = :ttl"),
		ConditionExpression:      aws.String("attribute_not_exists(#n) OR #n < :limit"),
		ExpressionAttributeNames: map[string]string{"#n": "requests"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":one":   &types.AttributeValueMemberN{Value: "1"},
			":limit": &types.AttributeValueMemberN{Value: strconv.Itoa(limit)},
			":ttl":   &types.AttributeValueMemberN{Value: end},
		},
	})
	var over *types.ConditionalCheckFailedException
	switch {
	case errors.As(err, &over):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("failed to count request for %s: %w", key, err)
	}
	return true, nil
}

type commandItem struct {
	PK        string `dynamodbav:"pk"`
	SK        string `dynamodbav:"sk"`
	Deadline  int64  `dynamodbav:"deadline"`
	ExpiresAt int64  `dynamodbav:"expires_at"`
	CommandRecord
}

func commandKey(agentID, id string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		attrPK: &types.AttributeValueMemberS{Value: agentPrefix + agentID},
		attrSK: &types.AttributeValueMemberS{Value: cmdPrefix + id},
	}
}

func (d *Dynamo) PutCommand(ctx context.Context, c CommandRecord) error {
	item, err := attributevalue.MarshalMap(commandItem{
		PK:            agentPrefix + c.AgentID,
		SK:            cmdPrefix + c.ID,
		Deadline:      c.ExpiresAt.UnixMilli(),
		ExpiresAt:     c.ExpiresAt.Add(commandRetention).Unix(),
		CommandRecord: c,
	})
	if err != nil {
		return fmt.Errorf("failed to encode command %s: %w", c.ID, err)
	}
	_, err = d.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           &d.table,
		Item:                item,
		ConditionExpression: aws.String("attribute_not_exists(pk)"),
	})
	if err != nil {
		return fmt.Errorf("failed to queue command %s for agent %s: %w", c.ID, c.AgentID, err)
	}
	return nil
}

func (d *Dynamo) Commands(ctx context.Context, agentID string) ([]CommandRecord, error) {
	return d.commands(ctx, agentID, "begins_with(sk, :cmd)", map[string]types.AttributeValue{
		":cmd": &types.AttributeValueMemberS{Value: cmdPrefix},
	})
}

func (d *Dynamo) CommandsSince(ctx context.Context, agentID string, since time.Time) ([]CommandRecord, error) {
	return d.commands(ctx, agentID, "sk BETWEEN :from AND :to", map[string]types.AttributeValue{
		":from": &types.AttributeValueMemberS{Value: cmdPrefix + commandIDFloor(since)},
		":to":   &types.AttributeValueMemberS{Value: cmdPrefix + commandIDCeiling},
	})
}

// commands reads an agent's commands whose sort keys meet skCondition.
func (d *Dynamo) commands(ctx context.Context, agentID, skCondition string, values map[string]types.AttributeValue) ([]CommandRecord, error) {
	var out []CommandRecord
	values[":pk"] = &types.AttributeValueMemberS{Value: agentPrefix + agentID}
	in := &dynamodb.QueryInput{
		TableName:                 &d.table,
		KeyConditionExpression:    aws.String("pk = :pk AND " + skCondition),
		ExpressionAttributeValues: values,
		ConsistentRead:            aws.Bool(true),
	}
	for {
		res, err := d.api.Query(ctx, in)
		if err != nil {
			return nil, fmt.Errorf("failed to read commands of agent %s: %w", agentID, err)
		}
		for _, raw := range res.Items {
			var item commandItem
			if err := attributevalue.UnmarshalMap(raw, &item); err != nil {
				return nil, fmt.Errorf("failed to decode command of agent %s: %w", agentID, err)
			}
			out = append(out, item.CommandRecord)
		}
		if len(res.LastEvaluatedKey) == 0 {
			return out, nil
		}
		in.ExclusiveStartKey = res.LastEvaluatedKey
	}
}

func (d *Dynamo) Command(ctx context.Context, agentID, id string) (CommandRecord, bool, error) {
	res, err := d.api.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      &d.table,
		Key:            commandKey(agentID, id),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return CommandRecord{}, false, fmt.Errorf("failed to read command %s of agent %s: %w", id, agentID, err)
	}
	if len(res.Item) == 0 {
		return CommandRecord{}, false, nil
	}
	var item commandItem
	if err := attributevalue.UnmarshalMap(res.Item, &item); err != nil {
		return CommandRecord{}, false, fmt.Errorf("failed to decode command %s of agent %s: %w", id, agentID, err)
	}
	return item.CommandRecord, true, nil
}

func (d *Dynamo) LeaseCommand(ctx context.Context, agentID, id string, now time.Time) (bool, error) {
	at, err := attributevalue.Marshal(now)
	if err != nil {
		return false, fmt.Errorf("failed to encode lease time: %w", err)
	}
	// the secret reaches the agent in this lease's response and only there
	return d.updateCommand(ctx, agentID, id, CommandQueued, now,
		"SET #status = :to, leased_at = :at REMOVE secret",
		map[string]types.AttributeValue{
			":to": &types.AttributeValueMemberS{Value: CommandLeased},
			":at": at,
		})
}

func (d *Dynamo) FinishCommand(ctx context.Context, agentID, id, status, result, errMsg string, now time.Time) (bool, error) {
	at, err := attributevalue.Marshal(now)
	if err != nil {
		return false, fmt.Errorf("failed to encode finish time: %w", err)
	}
	update := "SET #status = :to, finished_at = :at"
	values := map[string]types.AttributeValue{
		":to": &types.AttributeValueMemberS{Value: status},
		":at": at,
	}
	if result != "" {
		update += ", #result = :result"
		values[":result"] = &types.AttributeValueMemberS{Value: result}
	}
	if errMsg != "" {
		update += ", #error = :error"
		values[":error"] = &types.AttributeValueMemberS{Value: errMsg}
	}
	return d.updateCommand(ctx, agentID, id, CommandLeased, now, update, values)
}

// updateCommand applies update to an existing, unexpired command in status
// from, and reports whether it did.
func (d *Dynamo) updateCommand(ctx context.Context, agentID, id, from string, now time.Time, update string, values map[string]types.AttributeValue) (bool, error) {
	values[":from"] = &types.AttributeValueMemberS{Value: from}
	values[":now"] = &types.AttributeValueMemberN{Value: strconv.FormatInt(now.UnixMilli(), 10)}
	names := map[string]string{"#status": "status"}
	if strings.Contains(update, "#result") {
		names["#result"] = "result"
	}
	if strings.Contains(update, "#error") {
		names["#error"] = "error"
	}
	_, err := d.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 &d.table,
		Key:                       commandKey(agentID, id),
		UpdateExpression:          aws.String(update),
		ConditionExpression:       aws.String("attribute_exists(pk) AND #status = :from AND " + attrDeadline + " > :now"),
		ExpressionAttributeNames:  names,
		ExpressionAttributeValues: values,
	})
	var failed *types.ConditionalCheckFailedException
	switch {
	case errors.As(err, &failed):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("failed to update command %s of agent %s: %w", id, agentID, err)
	}
	return true, nil
}

type escrowItem struct {
	PK          string            `dynamodbav:"pk"`
	SK          string            `dynamodbav:"sk"`
	Fingerprint string            `dynamodbav:"fingerprint"`
	Certificate string            `dynamodbav:"certificate"`
	KeyID       string            `dynamodbav:"kms_key_id"`
	WrappedKey  string            `dynamodbav:"wrapped_key"`
	Nonce       string            `dynamodbav:"nonce"`
	Ciphertext  string            `dynamodbav:"ciphertext"`
	Context     map[string]string `dynamodbav:"encryption_context"`
	UploadedBy  string            `dynamodbav:"uploaded_by"`
	UploadedAt  time.Time         `dynamodbav:"uploaded_at"`
	// Copies, on the primary record only, lists the agents that stored a
	// further copy, so one read tells who escrowed a key.
	Copies []string `dynamodbav:"copies,stringset,omitempty"`
}

func newEscrowItem(sk string, rec protocol.EscrowRecord) escrowItem {
	return escrowItem{
		PK:          keyPrefix + rec.Fingerprint,
		SK:          sk,
		Fingerprint: rec.Fingerprint,
		Certificate: rec.Certificate,
		KeyID:       rec.Envelope.KeyID,
		WrappedKey:  rec.Envelope.WrappedKey,
		Nonce:       rec.Envelope.Nonce,
		Ciphertext:  rec.Envelope.Ciphertext,
		Context:     rec.Envelope.Context,
		UploadedBy:  rec.UploadedBy,
		UploadedAt:  rec.UploadedAt,
	}
}

func (e escrowItem) record() protocol.EscrowRecord {
	return protocol.EscrowRecord{
		Fingerprint: e.Fingerprint,
		Certificate: e.Certificate,
		Envelope: protocol.Envelope{
			KeyID:      e.KeyID,
			WrappedKey: e.WrappedKey,
			Nonce:      e.Nonce,
			Ciphertext: e.Ciphertext,
			Context:    e.Context,
		},
		UploadedBy: e.UploadedBy,
		UploadedAt: e.UploadedAt,
	}
}

func escrowKey(fingerprint string) map[string]types.AttributeValue {
	return itemKey(keyPrefix+fingerprint, skEscrow)
}

func (d *Dynamo) PutEscrow(ctx context.Context, rec protocol.EscrowRecord, maxCopies int) (bool, bool, error) {
	primary, err := attributevalue.MarshalMap(newEscrowItem(skEscrow, rec))
	if err != nil {
		return false, false, fmt.Errorf("failed to encode escrow of key %s: %w", rec.Fingerprint, err)
	}
	_, err = d.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           &d.table,
		Item:                primary,
		ConditionExpression: aws.String("attribute_not_exists(pk)"),
	})
	switch {
	case err == nil:
		return true, true, nil
	case !conditionFailed(err):
		return false, false, fmt.Errorf("failed to store escrow of key %s: %w", rec.Fingerprint, err)
	case maxCopies <= 1:
		return false, false, nil
	}

	// a further copy, listed on the primary record in the same write, which
	// is where the bound and the one copy per agent are enforced
	copyItem, err := attributevalue.MarshalMap(newEscrowItem(escrowCopyPrefix+rec.UploadedBy, rec))
	if err != nil {
		return false, false, fmt.Errorf("failed to encode escrow of key %s: %w", rec.Fingerprint, err)
	}
	_, err = d.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{Put: &types.Put{
				TableName:           &d.table,
				Item:                copyItem,
				ConditionExpression: aws.String("attribute_not_exists(pk)"),
			}},
			{Update: &types.Update{
				TableName:        &d.table,
				Key:              escrowKey(rec.Fingerprint),
				UpdateExpression: aws.String("ADD copies :agents"),
				ConditionExpression: aws.String("uploaded_by <> :agent AND " +
					"(attribute_not_exists(copies) OR (size(copies) < :others AND NOT contains(copies, :agent)))"),
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":agents": &types.AttributeValueMemberSS{Value: []string{rec.UploadedBy}},
					":agent":  &types.AttributeValueMemberS{Value: rec.UploadedBy},
					":others": &types.AttributeValueMemberN{Value: strconv.Itoa(maxCopies - 1)},
				},
			}},
		},
	})
	switch {
	case conditionFailed(err):
		return false, false, nil
	case err != nil:
		return false, false, fmt.Errorf("failed to store escrow copy of key %s from %s: %w", rec.Fingerprint, rec.UploadedBy, err)
	}
	return true, false, nil
}

func (d *Dynamo) Escrow(ctx context.Context, fingerprint string) ([]protocol.EscrowRecord, error) {
	in := &dynamodb.QueryInput{
		TableName:              &d.table,
		KeyConditionExpression: aws.String("pk = :pk AND begins_with(sk, :escrow)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk":     &types.AttributeValueMemberS{Value: keyPrefix + fingerprint},
			":escrow": &types.AttributeValueMemberS{Value: skEscrow},
		},
		ConsistentRead: aws.Bool(true),
	}
	var items []escrowItem
	for {
		res, err := d.api.Query(ctx, in)
		if err != nil {
			return nil, fmt.Errorf("failed to read escrow of key %s: %w", fingerprint, err)
		}
		for _, raw := range res.Items {
			var item escrowItem
			if err := attributevalue.UnmarshalMap(raw, &item); err != nil {
				return nil, fmt.Errorf("failed to decode escrow of key %s: %w", fingerprint, err)
			}
			items = append(items, item)
		}
		if len(res.LastEvaluatedKey) == 0 {
			break
		}
		in.ExclusiveStartKey = res.LastEvaluatedKey
	}
	// the primary record (skEscrow) sorts before its copies (ESCROW#<agent>)
	sort.Slice(items, func(i, j int) bool { return items[i].SK < items[j].SK })
	out := make([]protocol.EscrowRecord, 0, len(items))
	for _, item := range items {
		out = append(out, item.record())
	}
	return out, nil
}

func (d *Dynamo) EscrowUploaders(ctx context.Context, fingerprints []string) (map[string][]string, error) {
	keys := make([]map[string]types.AttributeValue, 0, len(fingerprints))
	seen := map[string]bool{}
	for _, fp := range fingerprints {
		// BatchGetItem refuses duplicate keys
		if !seen[fp] {
			seen[fp] = true
			keys = append(keys, escrowKey(fp))
		}
	}
	out := map[string][]string{}
	err := d.batchGet(ctx, keys, "fingerprint, uploaded_by, copies", func(raw map[string]types.AttributeValue) error {
		var item escrowItem
		if err := attributevalue.UnmarshalMap(raw, &item); err != nil {
			return fmt.Errorf("failed to decode escrow record: %w", err)
		}
		copies := slices.Clone(item.Copies)
		sort.Strings(copies)
		out[item.Fingerprint] = append([]string{item.UploadedBy}, copies...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to read escrow records: %w", err)
	}
	return out, nil
}

// EnsureTable creates the table if it does not exist and waits until it is
// active. Real deployments create the table with infrastructure code; this
// is for local emulators and tests.
func (d *Dynamo) EnsureTable(ctx context.Context) error {
	_, err := d.api.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName:   &d.table,
		BillingMode: types.BillingModePayPerRequest,
		AttributeDefinitions: []types.AttributeDefinition{
			{AttributeName: aws.String(attrPK), AttributeType: types.ScalarAttributeTypeS},
			{AttributeName: aws.String(attrSK), AttributeType: types.ScalarAttributeTypeS},
		},
		KeySchema: []types.KeySchemaElement{
			{AttributeName: aws.String(attrPK), KeyType: types.KeyTypeHash},
			{AttributeName: aws.String(attrSK), KeyType: types.KeyTypeRange},
		},
	})
	var inUse *types.ResourceInUseException
	if err != nil && !errors.As(err, &inUse) {
		return fmt.Errorf("failed to create table %s: %w", d.table, err)
	}
	for {
		out, err := d.api.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: &d.table})
		if err != nil {
			return fmt.Errorf("failed to describe table %s: %w", d.table, err)
		}
		if out.Table != nil && out.Table.TableStatus == types.TableStatusActive {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

var _ Store = (*Dynamo)(nil)
