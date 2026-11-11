package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// Resealing's item keys; see docs/design.md, section 11.
const (
	// resealPK holds an env's schedules, runs and reseal pull requests
	resealPK = "RESEAL"
	// fileResealPrefix keys a file reseal in its session's partition
	fileResealPrefix = "RESEAL#"
)

type fileResealItem struct {
	PK        string `dynamodbav:"pk"`
	SK        string `dynamodbav:"sk"`
	ExpiresAt int64  `dynamodbav:"expires_at"`
	FileReseal
}

type pullItem struct {
	PK string `dynamodbav:"pk"`
	SK string `dynamodbav:"sk"`
	// ExpiresAt is set once the pull request is merged or closed
	ExpiresAt int64 `dynamodbav:"expires_at,omitempty"`
	ResealPullRequest
}

func (d *Dynamo) PutFileReseal(ctx context.Context, r FileReseal) error {
	if r.Outcomes == nil {
		// outcomes are set one by one under it
		r.Outcomes = map[string]ResealOutcome{}
	}
	item, err := attributevalue.MarshalMap(fileResealItem{
		PK:         sessionPrefix + r.SessionID,
		SK:         fileResealPrefix + r.ID,
		ExpiresAt:  r.ExpiresAt.Unix(),
		FileReseal: r,
	})
	if err != nil {
		return fmt.Errorf("failed to encode reseal %s: %w", r.ID, err)
	}
	_, err = d.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           &d.table,
		Item:                item,
		ConditionExpression: aws.String("attribute_not_exists(pk)"),
	})
	if err != nil {
		return fmt.Errorf("failed to store reseal %s: %w", r.ID, err)
	}
	return nil
}

func (d *Dynamo) FileReseal(ctx context.Context, sessionID, id string) (FileReseal, bool, error) {
	var item fileResealItem
	found, err := d.getItem(ctx, sessionPrefix+sessionID, fileResealPrefix+id, &item)
	if err != nil {
		return FileReseal{}, false, fmt.Errorf("failed to read reseal %s: %w", id, err)
	}
	return item.FileReseal, found, nil
}

func (d *Dynamo) RecordResealOutcome(ctx context.Context, sessionID, id, commandID string, o ResealOutcome) (bool, error) {
	v, err := attributevalue.Marshal(o)
	if err != nil {
		return false, fmt.Errorf("failed to encode the outcome of command %s: %w", commandID, err)
	}
	// each command sets its own entry, so commands that finish at once do
	// not overwrite each other
	_, err = d.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 &d.table,
		Key:                       itemKey(sessionPrefix+sessionID, fileResealPrefix+id),
		UpdateExpression:          aws.String("SET outcomes.#c = :o"),
		ConditionExpression:       aws.String("attribute_exists(pk) AND attribute_not_exists(outcomes.#c)"),
		ExpressionAttributeNames:  map[string]string{"#c": commandID},
		ExpressionAttributeValues: map[string]types.AttributeValue{":o": v},
	})
	var failed *types.ConditionalCheckFailedException
	switch {
	case errors.As(err, &failed):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("failed to record the outcome of command %s of reseal %s: %w", commandID, id, err)
	}
	return true, nil
}

func (d *Dynamo) PutResealPullRequest(ctx context.Context, p ResealPullRequest) error {
	if err := p.check(); err != nil {
		return fmt.Errorf("failed to record a reseal pull request: %w", err)
	}
	item, err := attributevalue.MarshalMap(pullItem{PK: resealPK, SK: pullSortKey(true, p.RepoKey(), p.Number), ResealPullRequest: p})
	if err != nil {
		return fmt.Errorf("failed to encode pull request %s#%d: %w", p.Repo, p.Number, err)
	}
	if _, err := d.api.PutItem(ctx, &dynamodb.PutItemInput{TableName: &d.table, Item: item}); err != nil {
		return fmt.Errorf("failed to record pull request %s#%d: %w", p.Repo, p.Number, err)
	}
	return nil
}

func (d *Dynamo) ResealPullRequests(ctx context.Context, open bool, repoKey string) ([]ResealPullRequest, error) {
	prefix := pullDonePrefix
	if open {
		prefix = pullOpenPrefix
	}
	if repoKey != "" {
		prefix += repoKey + "#"
	}
	now := time.Now()
	out := []ResealPullRequest{}
	err := d.query(ctx, resealPK, prefix, nil, func(raw map[string]types.AttributeValue) error {
		var item pullItem
		if err := attributevalue.UnmarshalMap(raw, &item); err != nil {
			return fmt.Errorf("failed to decode a reseal pull request: %w", err)
		}
		// TTL deletion is eventual
		if item.ExpiresAt == 0 || item.ExpiresAt > now.Unix() {
			out = append(out, item.ResealPullRequest)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to read reseal pull requests: %w", err)
	}
	return out, nil
}

func (d *Dynamo) UpdateResealPullRequest(ctx context.Context, p ResealPullRequest) (bool, error) {
	if err := p.check(); err != nil {
		return false, fmt.Errorf("failed to update a reseal pull request: %w", err)
	}
	openKey := itemKey(resealPK, pullSortKey(true, p.RepoKey(), p.Number))
	if p.State == PullOpen {
		item, err := attributevalue.MarshalMap(pullItem{PK: resealPK, SK: pullSortKey(true, p.RepoKey(), p.Number), ResealPullRequest: p})
		if err != nil {
			return false, fmt.Errorf("failed to encode pull request %s#%d: %w", p.Repo, p.Number, err)
		}
		_, err = d.api.PutItem(ctx, &dynamodb.PutItemInput{
			TableName:           &d.table,
			Item:                item,
			ConditionExpression: aws.String("attribute_exists(pk)"),
		})
		if conditionFailed(err) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("failed to update pull request %s#%d: %w", p.Repo, p.Number, err)
		}
		return true, nil
	}
	item, err := attributevalue.MarshalMap(pullItem{
		PK:                resealPK,
		SK:                pullSortKey(false, p.RepoKey(), p.Number),
		ExpiresAt:         p.endedAt().Add(ResealRetention).Unix(),
		ResealPullRequest: p,
	})
	if err != nil {
		return false, fmt.Errorf("failed to encode pull request %s#%d: %w", p.Repo, p.Number, err)
	}
	// out of the open ones and among the ended ones in one write
	_, err = d.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
		{Delete: &types.Delete{TableName: &d.table, Key: openKey, ConditionExpression: aws.String("attribute_exists(pk)")}},
		{Put: &types.Put{TableName: &d.table, Item: item}},
	}})
	if conditionFailed(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to record pull request %s#%d as %s: %w", p.Repo, p.Number, p.State, err)
	}
	return true, nil
}

// getItem reads one item into out with a consistent read, and reports
// whether it exists.
func (d *Dynamo) getItem(ctx context.Context, pk, sk string, out any) (bool, error) {
	res, err := d.api.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      &d.table,
		Key:            itemKey(pk, sk),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return false, err
	}
	if len(res.Item) == 0 {
		return false, nil
	}
	if err := attributevalue.UnmarshalMap(res.Item, out); err != nil {
		return false, fmt.Errorf("failed to decode item: %w", err)
	}
	return true, nil
}
