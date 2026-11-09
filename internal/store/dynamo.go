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

// Item keys; see docs/design.md, section 11.
const (
	attrPK = "pk"
	attrSK = "sk"

	agentPrefix = "AGENT#"
	keyPrefix   = "KEY#"
	skState     = "STATE"
	skMeta      = "META"

	// batchGetLimit is DynamoDB's BatchGetItem maximum.
	batchGetLimit = 100
)

// DynamoAPI is the subset of the DynamoDB client the store uses.
type DynamoAPI interface {
	PutItem(ctx context.Context, in *dynamodb.PutItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	BatchGetItem(ctx context.Context, in *dynamodb.BatchGetItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.BatchGetItemOutput, error)
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
	out := map[string]AgentState{}
	for start := 0; start < len(ids); start += batchGetLimit {
		end := min(start+batchGetLimit, len(ids))
		keys := make([]map[string]types.AttributeValue, 0, end-start)
		for _, id := range ids[start:end] {
			keys = append(keys, agentKey(id))
		}
		request := map[string]types.KeysAndAttributes{d.table: {Keys: keys, ConsistentRead: aws.Bool(true)}}
		for attempt := 0; len(request) > 0; attempt++ {
			if attempt > 0 {
				if attempt > 5 {
					return nil, errors.New("failed to read agent states: unprocessed keys after retries")
				}
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(time.Duration(attempt*50) * time.Millisecond):
				}
			}
			res, err := d.api.BatchGetItem(ctx, &dynamodb.BatchGetItemInput{RequestItems: request})
			if err != nil {
				return nil, fmt.Errorf("failed to read agent states: %w", err)
			}
			for _, raw := range res.Responses[d.table] {
				var item agentItem
				if err := attributevalue.UnmarshalMap(raw, &item); err != nil {
					return nil, fmt.Errorf("failed to decode agent state: %w", err)
				}
				out[item.AgentID] = item.AgentState
			}
			request = res.UnprocessedKeys
		}
	}
	return out, nil
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
