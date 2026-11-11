package store

import (
	"context"
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

// Item keys of schedules and runs; see docs/design.md, section 11.
const (
	schedulePrefix = "SCHEDULE#"
	// skSchedules counts an env's schedules, so the cap holds under
	// concurrent requests
	skSchedules = "SCHEDULES"
	runPrefix   = "RUN#"
	// in a run's partition
	runRepoPrefix  = "REPO#"
	runWorkPrefix  = "WORK#"
	runBatchPrefix = "BATCH#"
	runDonePrefix  = "DONE#"
	// keyCeiling sorts after every repository key and command ID
	keyCeiling = "~"
)

type scheduleItem struct {
	PK string `dynamodbav:"pk"`
	SK string `dynamodbav:"sk"`
	ResealSchedule
}

type runItem struct {
	PK string `dynamodbav:"pk"`
	SK string `dynamodbav:"sk"`
	// ExpiresAt is set once the run ends
	ExpiresAt int64 `dynamodbav:"expires_at,omitempty"`
	ResealRun
}

type runRepoItem struct {
	PK        string `dynamodbav:"pk"`
	SK        string `dynamodbav:"sk"`
	ExpiresAt int64  `dynamodbav:"expires_at"`
	ResealRunRepo
}

type workItem struct {
	PK        string `dynamodbav:"pk"`
	SK        string `dynamodbav:"sk"`
	ExpiresAt int64  `dynamodbav:"expires_at"`
	ResealWork
}

type batchItem struct {
	PK        string `dynamodbav:"pk"`
	SK        string `dynamodbav:"sk"`
	ExpiresAt int64  `dynamodbav:"expires_at"`
	ResealBatch
}

func (d *Dynamo) CreateResealSchedule(ctx context.Context, s ResealSchedule, maxSchedules int) error {
	item, err := attributevalue.MarshalMap(scheduleItem{PK: resealPK, SK: schedulePrefix + s.ID, ResealSchedule: s})
	if err != nil {
		return fmt.Errorf("failed to encode schedule %s: %w", s.ID, err)
	}
	_, err = d.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
		{Update: &types.Update{
			TableName:                 &d.table,
			Key:                       itemKey(resealPK, skSchedules),
			UpdateExpression:          aws.String("ADD #n :one"),
			ConditionExpression:       aws.String("attribute_not_exists(#n) OR #n < :max"),
			ExpressionAttributeNames:  map[string]string{"#n": "schedules"},
			ExpressionAttributeValues: map[string]types.AttributeValue{":one": number(1), ":max": number(int64(maxSchedules))},
		}},
		{Put: &types.Put{TableName: &d.table, Item: item, ConditionExpression: aws.String("attribute_not_exists(pk)")}},
	}})
	if failed, ok := failedConditions(err); ok && failed[0] {
		return ErrTooManySchedules
	}
	if err != nil {
		return fmt.Errorf("failed to store schedule %s: %w", s.ID, err)
	}
	return nil
}

func (d *Dynamo) ResealSchedules(ctx context.Context) ([]ResealSchedule, error) {
	out := []ResealSchedule{}
	err := d.query(ctx, resealPK, schedulePrefix, nil, func(raw map[string]types.AttributeValue) error {
		var item scheduleItem
		if err := attributevalue.UnmarshalMap(raw, &item); err != nil {
			return fmt.Errorf("failed to decode schedule: %w", err)
		}
		out = append(out, item.ResealSchedule)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to read schedules: %w", err)
	}
	return out, nil
}

func (d *Dynamo) ResealSchedule(ctx context.Context, id string) (ResealSchedule, bool, error) {
	var item scheduleItem
	found, err := d.getItem(ctx, resealPK, schedulePrefix+id, &item)
	if err != nil {
		return ResealSchedule{}, false, fmt.Errorf("failed to read schedule %s: %w", id, err)
	}
	return item.ResealSchedule, found, nil
}

func (d *Dynamo) UpdateResealSchedule(ctx context.Context, s ResealSchedule) (bool, error) {
	values := map[string]types.AttributeValue{}
	sets := []string{}
	for name, v := range map[string]any{
		"name": s.Name, "repos": s.Repos, "orgs": s.Orgs, "interval_days": s.IntervalDays,
		"enabled": s.Enabled, "updated_by": s.UpdatedBy, "updated_at": s.UpdatedAt,
	} {
		av, err := attributevalue.Marshal(v)
		if err != nil {
			return false, fmt.Errorf("failed to encode schedule %s: %w", s.ID, err)
		}
		values[":"+name] = av
		sets = append(sets, "#"+name+" = :"+name)
	}
	sort.Strings(sets)
	names := map[string]string{}
	for _, n := range []string{"name", "repos", "orgs", "interval_days", "enabled", "updated_by", "updated_at", "next_run_at"} {
		names["#"+n] = n
	}
	update := "SET " + strings.Join(sets, ", ")
	if s.NextRunAt != nil {
		av, err := attributevalue.Marshal(s.NextRunAt)
		if err != nil {
			return false, fmt.Errorf("failed to encode schedule %s: %w", s.ID, err)
		}
		values[":next_run_at"] = av
		update += ", #next_run_at = :next_run_at"
	} else {
		update += " REMOVE #next_run_at"
	}
	_, err := d.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 &d.table,
		Key:                       itemKey(resealPK, schedulePrefix+s.ID),
		UpdateExpression:          aws.String(update),
		ConditionExpression:       aws.String("attribute_exists(pk)"),
		ExpressionAttributeNames:  names,
		ExpressionAttributeValues: values,
	})
	if conditionFailed(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to update schedule %s: %w", s.ID, err)
	}
	return true, nil
}

func (d *Dynamo) DeleteResealSchedule(ctx context.Context, id string) (ResealSchedule, bool, error) {
	// the active run returned must be the one deleted with it: a run
	// started meanwhile makes it read again
	for range maxReserveAttempts {
		s, found, err := d.ResealSchedule(ctx, id)
		if err != nil || !found {
			return ResealSchedule{}, false, err
		}
		condition := "attribute_exists(pk) AND attribute_not_exists(active_run_id)"
		var values map[string]types.AttributeValue
		if s.ActiveRunID != "" {
			condition = "active_run_id = :run"
			values = map[string]types.AttributeValue{":run": &types.AttributeValueMemberS{Value: s.ActiveRunID}}
		}
		_, err = d.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
			{Delete: &types.Delete{
				TableName: &d.table, Key: itemKey(resealPK, schedulePrefix+id),
				ConditionExpression: aws.String(condition), ExpressionAttributeValues: values,
			}},
			{Update: &types.Update{
				TableName:                 &d.table,
				Key:                       itemKey(resealPK, skSchedules),
				UpdateExpression:          aws.String("ADD #n :less"),
				ExpressionAttributeNames:  map[string]string{"#n": "schedules"},
				ExpressionAttributeValues: map[string]types.AttributeValue{":less": number(-1)},
			}},
		}})
		if failed, ok := failedConditions(err); ok && failed[0] {
			// deleted, or a run started or ended, meanwhile
			continue
		}
		if err != nil {
			return ResealSchedule{}, false, fmt.Errorf("failed to delete schedule %s: %w", id, err)
		}
		return s, true, nil
	}
	return ResealSchedule{}, false, fmt.Errorf("failed to delete schedule %s: it kept changing", id)
}

func (d *Dynamo) StartResealRun(ctx context.Context, run ResealRun, expectNext, next *time.Time) error {
	item, err := attributevalue.MarshalMap(runItem{PK: resealPK, SK: runPrefix + run.ID, ResealRun: run})
	if err != nil {
		return fmt.Errorf("failed to encode run %s: %w", run.ID, err)
	}
	condition := "attribute_exists(pk) AND attribute_not_exists(active_run_id)"
	update := "SET active_run_id = :run, last_run_id = :run"
	values := map[string]types.AttributeValue{":run": &types.AttributeValueMemberS{Value: run.ID}}
	if expectNext != nil {
		expected, err := attributevalue.Marshal(expectNext)
		if err != nil {
			return fmt.Errorf("failed to encode run %s: %w", run.ID, err)
		}
		condition += " AND next_run_at = :expected"
		values[":expected"] = expected
		if next != nil {
			v, err := attributevalue.Marshal(next)
			if err != nil {
				return fmt.Errorf("failed to encode run %s: %w", run.ID, err)
			}
			update += ", next_run_at = :next"
			values[":next"] = v
		}
	}
	_, err = d.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
		{Put: &types.Put{TableName: &d.table, Item: item, ConditionExpression: aws.String("attribute_not_exists(pk)")}},
		{Update: &types.Update{
			TableName:                 &d.table,
			Key:                       itemKey(resealPK, schedulePrefix+run.ScheduleID),
			UpdateExpression:          aws.String(update),
			ConditionExpression:       aws.String(condition),
			ExpressionAttributeValues: values,
		}},
	}})
	if failed, ok := failedConditions(err); ok && failed[1] {
		return d.whyNotStarted(ctx, run.ScheduleID)
	}
	if err != nil {
		return fmt.Errorf("failed to start a run of schedule %s: %w", run.ScheduleID, err)
	}
	return nil
}

// whyNotStarted says why a run of a schedule could not start.
func (d *Dynamo) whyNotStarted(ctx context.Context, scheduleID string) error {
	s, found, err := d.ResealSchedule(ctx, scheduleID)
	switch {
	case err != nil:
		return err
	case found && s.ActiveRunID != "":
		return ErrRunActive
	}
	return ErrScheduleChanged
}

func (d *Dynamo) ResealRun(ctx context.Context, id string) (ResealRun, bool, error) {
	var item runItem
	found, err := d.getItem(ctx, resealPK, runPrefix+id, &item)
	if err != nil {
		return ResealRun{}, false, fmt.Errorf("failed to read run %s: %w", id, err)
	}
	return item.ResealRun, found, nil
}

func (d *Dynamo) ResealRuns(ctx context.Context, scheduleID string, limit int) ([]ResealRun, error) {
	in := &dynamodb.QueryInput{
		TableName:              &d.table,
		KeyConditionExpression: aws.String("pk = :pk AND sk BETWEEN :from AND :to"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk":   &types.AttributeValueMemberS{Value: resealPK},
			":from": &types.AttributeValueMemberS{Value: runPrefix},
			":to":   &types.AttributeValueMemberS{Value: runPrefix + keyCeiling},
		},
		// run IDs are ULIDs: newest first
		ScanIndexForward: aws.Bool(false),
		ConsistentRead:   aws.Bool(true),
	}
	if scheduleID != "" {
		in.FilterExpression = aws.String("schedule_id = :schedule")
		in.ExpressionAttributeValues[":schedule"] = &types.AttributeValueMemberS{Value: scheduleID}
	}
	now := time.Now().Unix()
	out := []ResealRun{}
	for len(out) < limit {
		res, err := d.api.Query(ctx, in)
		if err != nil {
			return nil, fmt.Errorf("failed to read runs: %w", err)
		}
		for _, raw := range res.Items {
			var item runItem
			if err := attributevalue.UnmarshalMap(raw, &item); err != nil {
				return nil, fmt.Errorf("failed to decode run: %w", err)
			}
			if (item.ExpiresAt == 0 || item.ExpiresAt > now) && len(out) < limit {
				out = append(out, item.ResealRun)
			}
		}
		if len(res.LastEvaluatedKey) == 0 {
			break
		}
		in.ExclusiveStartKey = res.LastEvaluatedKey
	}
	return out, nil
}

func (d *Dynamo) LeaseResealRun(ctx context.Context, id string, until, now time.Time) (ResealRun, bool, error) {
	res, err := d.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:        &d.table,
		Key:              itemKey(resealPK, runPrefix+id),
		UpdateExpression: aws.String("SET lease_until = :until"),
		ConditionExpression: aws.String("attribute_exists(pk) AND #status IN (:queued, :running) AND " +
			"(attribute_not_exists(lease_until) OR lease_until <= :now)"),
		ExpressionAttributeNames: map[string]string{"#status": "status"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":until":   millis(until),
			":now":     millis(now),
			":queued":  &types.AttributeValueMemberS{Value: RunQueued},
			":running": &types.AttributeValueMemberS{Value: RunRunning},
		},
		ReturnValues: types.ReturnValueAllNew,
	})
	if conditionFailed(err) {
		return ResealRun{}, false, nil
	}
	if err != nil {
		return ResealRun{}, false, fmt.Errorf("failed to lease run %s: %w", id, err)
	}
	var item runItem
	if err := attributevalue.UnmarshalMap(res.Attributes, &item); err != nil {
		return ResealRun{}, false, fmt.Errorf("failed to decode run %s: %w", id, err)
	}
	return item.ResealRun, true, nil
}

func (d *Dynamo) SaveResealRun(ctx context.Context, run ResealRun, held int64) (bool, error) {
	item := runItem{PK: resealPK, SK: runPrefix + run.ID, ResealRun: run}
	if !run.Active() && run.FinishedAt != nil {
		item.ExpiresAt = run.FinishedAt.Add(ResealRetention).Unix()
	}
	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return false, fmt.Errorf("failed to encode run %s: %w", run.ID, err)
	}
	condition := "#status IN (:queued, :running) AND "
	values := map[string]types.AttributeValue{
		":queued":  &types.AttributeValueMemberS{Value: RunQueued},
		":running": &types.AttributeValueMemberS{Value: RunRunning},
	}
	if held == 0 {
		condition += "attribute_not_exists(lease_until)"
	} else {
		condition += "lease_until = :held"
		values[":held"] = number(held)
	}
	_, err = d.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:                 &d.table,
		Item:                      av,
		ConditionExpression:       aws.String(condition),
		ExpressionAttributeNames:  map[string]string{"#status": "status"},
		ExpressionAttributeValues: values,
	})
	if conditionFailed(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to save run %s: %w", run.ID, err)
	}
	if !run.Active() {
		if err := d.endActiveRun(ctx, run.ScheduleID, run.ID); err != nil {
			return true, err
		}
	}
	return true, nil
}

func (d *Dynamo) CancelResealRun(ctx context.Context, id, by string, now time.Time) (ResealRun, bool, error) {
	at, err := attributevalue.Marshal(now)
	if err != nil {
		return ResealRun{}, false, fmt.Errorf("failed to encode cancellation time: %w", err)
	}
	res, err := d.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: &d.table,
		Key:       itemKey(resealPK, runPrefix+id),
		// a tick that holds a lease finds the run cancelled when it saves
		UpdateExpression:         aws.String("SET #status = :cancelled, finished_at = :at, cancelled_by = :by, expires_at = :ttl REMOVE lease_until"),
		ConditionExpression:      aws.String("attribute_exists(pk) AND #status IN (:queued, :running)"),
		ExpressionAttributeNames: map[string]string{"#status": "status"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":cancelled": &types.AttributeValueMemberS{Value: RunCancelled},
			":at":        at,
			":by":        &types.AttributeValueMemberS{Value: by},
			":ttl":       number(now.Add(ResealRetention).Unix()),
			":queued":    &types.AttributeValueMemberS{Value: RunQueued},
			":running":   &types.AttributeValueMemberS{Value: RunRunning},
		},
		ReturnValues: types.ReturnValueAllNew,
	})
	if conditionFailed(err) {
		return ResealRun{}, false, nil
	}
	if err != nil {
		return ResealRun{}, false, fmt.Errorf("failed to cancel run %s: %w", id, err)
	}
	var item runItem
	if err := attributevalue.UnmarshalMap(res.Attributes, &item); err != nil {
		return ResealRun{}, false, fmt.Errorf("failed to decode run %s: %w", id, err)
	}
	if err := d.endActiveRun(ctx, item.ScheduleID, id); err != nil {
		return item.ResealRun, true, err
	}
	return item.ResealRun, true, nil
}

// endActiveRun takes a run off its schedule's active run, if it is still
// that; a deleted schedule has none.
func (d *Dynamo) endActiveRun(ctx context.Context, scheduleID, runID string) error {
	_, err := d.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 &d.table,
		Key:                       itemKey(resealPK, schedulePrefix+scheduleID),
		UpdateExpression:          aws.String("REMOVE active_run_id"),
		ConditionExpression:       aws.String("active_run_id = :run"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":run": &types.AttributeValueMemberS{Value: runID}},
	})
	if err != nil && !conditionFailed(err) {
		return fmt.Errorf("failed to end the active run of schedule %s: %w", scheduleID, err)
	}
	return nil
}

func (d *Dynamo) PutResealRunRepos(ctx context.Context, repos []ResealRunRepo) error {
	expires := time.Now().Add(ResealRetention).Unix()
	for _, r := range repos {
		item, err := attributevalue.MarshalMap(runRepoItem{PK: runPrefix + r.RunID, SK: runRepoPrefix + r.Key, ExpiresAt: expires, ResealRunRepo: r})
		if err != nil {
			return fmt.Errorf("failed to encode repository %s of run %s: %w", r.Key, r.RunID, err)
		}
		if _, err := d.api.PutItem(ctx, &dynamodb.PutItemInput{TableName: &d.table, Item: item}); err != nil {
			return fmt.Errorf("failed to record repository %s of run %s: %w", r.Key, r.RunID, err)
		}
	}
	return nil
}

func (d *Dynamo) ResealRunRepo(ctx context.Context, runID, key string) (ResealRunRepo, bool, error) {
	var item runRepoItem
	found, err := d.getItem(ctx, runPrefix+runID, runRepoPrefix+key, &item)
	if err != nil {
		return ResealRunRepo{}, false, fmt.Errorf("failed to read repository %s of run %s: %w", key, runID, err)
	}
	return item.ResealRunRepo, found, nil
}

func (d *Dynamo) ResealRunRepos(ctx context.Context, runID string) ([]ResealRunRepo, error) {
	return d.runRepos(ctx, runID, runRepoPrefix, 0)
}

func (d *Dynamo) NextResealRunRepos(ctx context.Context, runID, after string, limit int) ([]ResealRunRepo, error) {
	from := runRepoPrefix
	if after != "" {
		// just past after: keys hold no control characters
		from += after + "\x00"
	}
	return d.runRepos(ctx, runID, from, limit)
}

// runRepos reads a run's repositories from the sort key from on, at most
// limit of them (0 for every one).
func (d *Dynamo) runRepos(ctx context.Context, runID, from string, limit int) ([]ResealRunRepo, error) {
	in := &dynamodb.QueryInput{
		TableName:              &d.table,
		KeyConditionExpression: aws.String("pk = :pk AND sk BETWEEN :from AND :to"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk":   &types.AttributeValueMemberS{Value: runPrefix + runID},
			":from": &types.AttributeValueMemberS{Value: from},
			":to":   &types.AttributeValueMemberS{Value: runRepoPrefix + keyCeiling},
		},
		ConsistentRead: aws.Bool(true),
	}
	if limit > 0 {
		in.Limit = aws.Int32(int32(min(limit, 1000)))
	}
	out := []ResealRunRepo{}
	for limit == 0 || len(out) < limit {
		res, err := d.api.Query(ctx, in)
		if err != nil {
			return nil, fmt.Errorf("failed to read the repositories of run %s: %w", runID, err)
		}
		for _, raw := range res.Items {
			var item runRepoItem
			if err := attributevalue.UnmarshalMap(raw, &item); err != nil {
				return nil, fmt.Errorf("failed to decode a repository of run %s: %w", runID, err)
			}
			out = append(out, item.ResealRunRepo)
		}
		if len(res.LastEvaluatedKey) == 0 {
			break
		}
		in.ExclusiveStartKey = res.LastEvaluatedKey
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (d *Dynamo) PutResealWork(ctx context.Context, w ResealWork) error {
	item, err := attributevalue.MarshalMap(workItem{
		PK: runPrefix + w.RunID, SK: runWorkPrefix + w.Key, ExpiresAt: time.Now().Add(resealWorkRetention).Unix(), ResealWork: w,
	})
	if err != nil {
		return fmt.Errorf("failed to encode the work on %s of run %s: %w", w.Key, w.RunID, err)
	}
	if _, err := d.api.PutItem(ctx, &dynamodb.PutItemInput{TableName: &d.table, Item: item}); err != nil {
		return fmt.Errorf("failed to record the work on %s of run %s: %w", w.Key, w.RunID, err)
	}
	return nil
}

func (d *Dynamo) ResealWork(ctx context.Context, runID, key string) (ResealWork, bool, error) {
	var item workItem
	found, err := d.getItem(ctx, runPrefix+runID, runWorkPrefix+key, &item)
	if err != nil {
		return ResealWork{}, false, fmt.Errorf("failed to read the work on %s of run %s: %w", key, runID, err)
	}
	return item.ResealWork, found, nil
}

func (d *Dynamo) PutResealBatch(ctx context.Context, b ResealBatch) (bool, error) {
	expires := time.Now().Add(resealWorkRetention).Unix()
	pk := runPrefix + b.RunID
	suffix := b.RepoKey + "#" + b.CommandID
	item, err := attributevalue.MarshalMap(batchItem{PK: pk, SK: runBatchPrefix + suffix, ExpiresAt: expires, ResealBatch: b})
	if err != nil {
		return false, fmt.Errorf("failed to encode the results of command %s: %w", b.CommandID, err)
	}
	// the batch and a small marker the run's ticks list, in one write
	_, err = d.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
		{Put: &types.Put{TableName: &d.table, Item: item, ConditionExpression: aws.String("attribute_not_exists(pk)")}},
		{Put: &types.Put{TableName: &d.table, Item: map[string]types.AttributeValue{
			attrPK:        &types.AttributeValueMemberS{Value: pk},
			attrSK:        &types.AttributeValueMemberS{Value: runDonePrefix + suffix},
			"command_id":  &types.AttributeValueMemberS{Value: b.CommandID},
			attrExpiresAt: number(expires),
		}}},
	}})
	if conditionFailed(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to record the results of command %s: %w", b.CommandID, err)
	}
	return true, nil
}

func (d *Dynamo) ResealBatchesDone(ctx context.Context, runID, repoKey string) ([]string, error) {
	var out []string
	err := d.query(ctx, runPrefix+runID, runDonePrefix+repoKey+"#", []string{"command_id"}, func(raw map[string]types.AttributeValue) error {
		if v, ok := raw["command_id"].(*types.AttributeValueMemberS); ok {
			out = append(out, v.Value)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to read the finished commands of %s in run %s: %w", repoKey, runID, err)
	}
	return out, nil
}

func (d *Dynamo) ResealBatch(ctx context.Context, runID, repoKey, commandID string) (ResealBatch, bool, error) {
	var item batchItem
	found, err := d.getItem(ctx, runPrefix+runID, runBatchPrefix+repoKey+"#"+commandID, &item)
	if err != nil {
		return ResealBatch{}, false, fmt.Errorf("failed to read the results of command %s: %w", commandID, err)
	}
	return item.ResealBatch, found, nil
}

func number(n int64) *types.AttributeValueMemberN {
	return &types.AttributeValueMemberN{Value: strconv.FormatInt(n, 10)}
}
