package connector

import (
	"context"
	"encoding/json"
	"net/url"
	"sort"
	"sync"
	"testing"
	"time"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	testRoleAcct   = "111111111111"
	testSyncedAcct = "222222222222"
	testOtherAcct  = "999999999999"
)

func trustDoc(t *testing.T, statements ...map[string]any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": statements})
	require.NoError(t, err)
	return url.QueryEscape(string(b))
}

func allowStmt(action any, principal any) map[string]any {
	return map[string]any{"Effect": "Allow", "Action": action, "Principal": principal}
}

func awsPrincipal(arns ...string) map[string]any {
	return map[string]any{"AWS": arns}
}

func testRole(t *testing.T) *v2.Resource {
	t.Helper()
	r, err := resourceSdk.NewRoleResource("target", resourceTypeRole,
		"arn:aws:iam::"+testRoleAcct+":role/target", nil)
	require.NoError(t, err)
	return r
}

func principalIDs(grants []*v2.Grant) []string {
	var out []string
	for _, g := range grants {
		out = append(out, g.GetPrincipal().GetId().GetResourceType()+"="+g.GetPrincipal().GetId().GetResource())
	}
	sort.Strings(out)
	return out
}

func TestHasAssumeRoleAction(t *testing.T) {
	tests := []struct {
		name    string
		actions Action
		want    bool
	}{
		{"AssumeRole", Action{"sts:AssumeRole"}, true},
		{"AssumeRoleWithSAML", Action{"sts:AssumeRoleWithSAML"}, true},
		{"AssumeRoleWithWebIdentity", Action{"sts:AssumeRoleWithWebIdentity"}, true},
		{"service wildcard", Action{"sts:*"}, true},
		{"global wildcard", Action{"*"}, true},
		{"prefix wildcard", Action{"sts:AssumeRole*"}, true},
		{"short prefix wildcard", Action{"sts:Assume*"}, true},
		{"question mark", Action{"sts:AssumeRol?"}, true},
		{"lower case", Action{"sts:assumerole"}, true},
		{"upper case", Action{"STS:ASSUMEROLE"}, true},
		{"mixed list", Action{"sts:TagSession", "sts:AssumeRole"}, true},
		{"wildcard in the middle", Action{"sts:*Role"}, true},
		{"tag session only", Action{"sts:TagSession"}, false},
		{"other service wildcard", Action{"s3:*"}, false},
		{"set context only", Action{"sts:SetSourceIdentity"}, false},
		{"question mark too short", Action{"sts:AssumeRo?"}, false},
		{"empty", Action{}, false},
		{"empty string", Action{""}, false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, hasAssumeRoleAction(tt.actions))
		})
	}
}

func TestIamGlobMatch(t *testing.T) {
	assert.True(t, iamGlobMatch("*", ""))
	assert.True(t, iamGlobMatch("a*b*c", "aXXbYYc"))
	assert.False(t, iamGlobMatch("a*b*c", "aXXbYY"))
	assert.True(t, iamGlobMatch("a?c", "abc"))
	assert.False(t, iamGlobMatch("a?c", "ac"))
	assert.True(t, iamGlobMatch("abc", "abc"))
	assert.False(t, iamGlobMatch("abc", "abcd"))
}

func TestExtractTrustPrincipalsByKind_DocumentShapes(t *testing.T) {
	user := "arn:aws:iam::" + testRoleAcct + ":user/alice"

	t.Run("single object statement", func(t *testing.T) {
		b, _ := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": allowStmt("sts:*", awsPrincipal(user))})
		tp, err := extractTrustPrincipalsByKind(url.QueryEscape(string(b)))
		require.NoError(t, err)
		assert.Equal(t, []string{user}, tp.aws)
	})
	t.Run("deny is ignored", func(t *testing.T) {
		deny := allowStmt("sts:AssumeRole", awsPrincipal(user))
		deny["Effect"] = "Deny"
		tp, err := extractTrustPrincipalsByKind(trustDoc(t, deny))
		require.NoError(t, err)
		assert.Empty(t, tp.aws)
	})
	t.Run("tag session only gives nothing", func(t *testing.T) {
		tp, err := extractTrustPrincipalsByKind(trustDoc(t, allowStmt("sts:TagSession", awsPrincipal(user))))
		require.NoError(t, err)
		assert.Empty(t, tp.aws)
	})
	t.Run("no action gives nothing", func(t *testing.T) {
		tp, err := extractTrustPrincipalsByKind(trustDoc(t, map[string]any{"Effect": "Allow", "Principal": awsPrincipal(user)}))
		require.NoError(t, err)
		assert.Empty(t, tp.aws)
	})
	t.Run("bare star principal gives nothing", func(t *testing.T) {
		tp, err := extractTrustPrincipalsByKind(trustDoc(t, allowStmt("sts:AssumeRole", "*")))
		require.NoError(t, err)
		assert.Empty(t, tp.aws)
	})
	t.Run("AWS star principal is returned", func(t *testing.T) {
		tp, err := extractTrustPrincipalsByKind(trustDoc(t, allowStmt("sts:AssumeRole", map[string]any{"AWS": "*"})))
		require.NoError(t, err)
		assert.Equal(t, []string{"*"}, tp.aws)
	})
	t.Run("grant wrapper and classifier share the rule", func(t *testing.T) {
		doc := trustDoc(t, allowStmt("STS:ASSUMEROLEWITHSAML", awsPrincipal(user)))
		got, err := extractTrustPrincipals(doc)
		require.NoError(t, err)
		assert.Equal(t, []string{user}, got)
	})
	t.Run("empty strings are dropped by the wrapper", func(t *testing.T) {
		got, err := extractTrustPrincipals(trustDoc(t, allowStmt("sts:AssumeRole", awsPrincipal("", user))))
		require.NoError(t, err)
		assert.Equal(t, []string{user}, got)
	})
}

func TestClassifyTrustPrincipals(t *testing.T) {
	roleArn := "arn:aws:iam::" + testRoleAcct + ":role/peer"
	syncedRole := "arn:aws:iam::" + testSyncedAcct + ":role/team/dev"
	syncedUser := "arn:aws:iam::" + testSyncedAcct + ":user/bob"
	otherRole := "arn:aws:iam::" + testOtherAcct + ":role/vendor"
	otherUser := "arn:aws:iam::" + testOtherAcct + ":user/vendor"

	ctx := trustGrantContext{roleAccountID: testRoleAcct, syncedAccounts: map[string]bool{testSyncedAcct: true}}

	tests := []struct {
		name      string
		aws       []string
		ctx       trustGrantContext
		wantIDs   []string
		wantSkips skipCounts
	}{
		{"role in the role account", []string{roleArn}, ctx, []string{"role=" + roleArn}, skipCounts{}},
		{"role and user in a synced account", []string{syncedRole, syncedUser}, ctx,
			[]string{"iam_user=" + syncedUser, "role=" + syncedRole}, skipCounts{}},
		{"role and user in an unsynced account", []string{otherRole, otherUser}, ctx, nil, skipCounts{NotSyncedAccount: 2}},
		{"role ARN with a path", []string{"arn:aws:iam::" + testRoleAcct + ":role/a/b/c"}, ctx,
			[]string{"role=arn:aws:iam::" + testRoleAcct + ":role/a/b/c"}, skipCounts{}},
		{"wildcards", []string{"*", "arn:aws:iam::*:role/x", "arn:aws:iam::" + testRoleAcct + ":role/*"}, ctx, nil, skipCounts{Wildcard: 3}},
		{"root and bare account id are unsupported", []string{"arn:aws:iam::" + testSyncedAcct + ":root", testSyncedAcct}, ctx, nil, skipCounts{Unsupported: 2}},
		{"assumed role and not an ARN are unsupported", []string{"arn:aws:sts::" + testRoleAcct + ":assumed-role/x/y", "bogus"}, ctx, nil, skipCounts{Unsupported: 2}},
		{"empty strings are ignored", []string{"", "  "}, ctx, nil, skipCounts{}},
		{"duplicates collapse", []string{syncedRole, syncedRole, " " + syncedRole}, ctx, []string{"role=" + syncedRole}, skipCounts{}},
		{"mixed", []string{roleArn, otherRole, "*", testSyncedAcct}, ctx,
			[]string{"role=" + roleArn}, skipCounts{NotSyncedAccount: 1, Wildcard: 1, Unsupported: 1}},
		{"fallback: no synced set, own account only", []string{roleArn, syncedRole},
			trustGrantContext{roleAccountID: testRoleAcct}, []string{"role=" + roleArn}, skipCounts{NotSyncedAccount: 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			refs, skips := classifyTrustPrincipals(trustPrincipals{aws: tt.aws}, tt.ctx)
			var ids []string
			for _, r := range refs {
				ids = append(ids, r.resourceType.Id+"="+r.id)
			}
			sort.Strings(ids)
			assert.Equal(t, tt.wantIDs, ids)
			assert.Equal(t, tt.wantSkips, skips)
		})
	}
}

func TestGrantsForTrust_Golden(t *testing.T) {
	role := testRole(t)
	peer := "arn:aws:iam::" + testRoleAcct + ":role/peer"
	syncedUser := "arn:aws:iam::" + testSyncedAcct + ":user/bob"
	other := "arn:aws:iam::" + testOtherAcct + ":role/vendor"
	ctx := trustGrantContext{roleAccountID: testRoleAcct, syncedAccounts: map[string]bool{testSyncedAcct: true}}

	tests := []struct {
		name       string
		doc        string
		wantIDs    []string
		wantSkips  skipCounts
		wantExpand []string
	}{
		{"exact action", trustDoc(t, allowStmt("sts:AssumeRole", awsPrincipal(peer, syncedUser, other))),
			[]string{"iam_user=" + syncedUser, "role=" + peer}, skipCounts{NotSyncedAccount: 1}, []string{peer}},
		{"D7 wildcard action", trustDoc(t, allowStmt("sts:*", awsPrincipal(peer))),
			[]string{"role=" + peer}, skipCounts{}, []string{peer}},
		{"D7 global wildcard", trustDoc(t, allowStmt([]string{"*"}, awsPrincipal(syncedUser))),
			[]string{"iam_user=" + syncedUser}, skipCounts{}, nil},
		{"D7 mixed case", trustDoc(t, allowStmt("STS:assumerole", awsPrincipal(peer))),
			[]string{"role=" + peer}, skipCounts{}, []string{peer}},
		{"tag session only", trustDoc(t, allowStmt("sts:TagSession", awsPrincipal(peer))), nil, skipCounts{}, nil},
		{"two statements dedupe", trustDoc(t,
			allowStmt("sts:AssumeRole", awsPrincipal(peer)), allowStmt("sts:TagSession", awsPrincipal(peer)),
			allowStmt("sts:AssumeRole", awsPrincipal(peer))),
			[]string{"role=" + peer}, skipCounts{}, []string{peer}},
		{"all skipped", trustDoc(t, allowStmt("sts:AssumeRole", awsPrincipal(other, "*", testOtherAcct))),
			nil, skipCounts{NotSyncedAccount: 1, Wildcard: 1, Unsupported: 1}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tp, err := extractTrustPrincipalsByKind(tt.doc)
			require.NoError(t, err)
			grants, skips, err := grantsForTrust(role, tp, ctx)
			require.NoError(t, err)
			assert.Equal(t, tt.wantIDs, principalIDs(grants))
			assert.Equal(t, tt.wantSkips, skips)

			var expand []string
			for _, g := range grants {
				assert.Equal(t, roleAssignmentEntitlement, g.GetEntitlement().GetId()[len(g.GetEntitlement().GetId())-len(roleAssignmentEntitlement):])
				assert.Equal(t, role.GetId().GetResource(), g.GetEntitlement().GetResource().GetId().GetResource())
				for _, a := range g.GetAnnotations() {
					ge := &v2.GrantExpandable{}
					if a.MessageIs(ge) {
						require.NoError(t, a.UnmarshalTo(ge))
						require.Len(t, ge.GetEntitlementIds(), 1)
						expand = append(expand, g.GetPrincipal().GetId().GetResource())
						assert.Equal(t, "role:"+g.GetPrincipal().GetId().GetResource()+":assignment", ge.GetEntitlementIds()[0])
					}
				}
			}
			sort.Strings(expand)
			assert.Equal(t, tt.wantExpand, expand)
		})
	}
}

func TestNHIClassification_BeforeAfter(t *testing.T) {
	cross := "arn:aws:iam::" + testOtherAcct + ":role/x"
	tests := []struct {
		name   string
		action any
		want   string
	}{
		{"exact (unchanged)", "sts:AssumeRole", "aws.role.cross_account"},
		{"prefix wildcard (unchanged)", "sts:AssumeRole*", "aws.role.cross_account"},
		{"sts star (was aws.role)", "sts:*", "aws.role.cross_account"},
		{"star (was aws.role)", "*", "aws.role.cross_account"},
		{"lower case (was aws.role)", "sts:assumerole", "aws.role.cross_account"},
		{"tag session (unchanged)", "sts:TagSession", "aws.role"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := trustDoc(t, allowStmt(tt.action, awsPrincipal(cross)))
			role := newTestIAMRole(testRoleAcct, doc)
			_, detail := classifyRoleNHI(context.Background(), role)
			assert.Equal(t, tt.want, detail)
		})
	}
}

func TestSyncedAccountsStore(t *testing.T) {
	ctx := context.Background()

	t.Run("missing marker means not ready", func(t *testing.T) {
		_, ready := loadSyncedAccounts(ctx, newMemorySessionStore(), []string{testSyncedAcct})
		assert.False(t, ready)
	})
	t.Run("nil store means not ready", func(t *testing.T) {
		_, ready := loadSyncedAccounts(ctx, nil, []string{testSyncedAcct})
		assert.False(t, ready)
	})
	t.Run("write then read", func(t *testing.T) {
		ss := newMemorySessionStore()
		rememberSyncedAccounts(ctx, ss, testRoleAcct, testSyncedAcct, "")
		synced, ready := loadSyncedAccounts(ctx, ss, []string{testSyncedAcct, testOtherAcct})
		require.True(t, ready)
		assert.True(t, synced[testSyncedAcct])
		assert.False(t, synced[testOtherAcct])
	})
	t.Run("store failure falls back", func(t *testing.T) {
		rememberSyncedAccounts(ctx, &failingSessionStore{}, testRoleAcct)
		_, ready := loadSyncedAccounts(ctx, &failingSessionStore{}, []string{testRoleAcct})
		assert.False(t, ready)
	})
}

func TestTrustGrantContext_FallbackLogsOncePerSync(t *testing.T) {
	core, logs := newLogRecorder()
	ctx := ctxWithLogger(zap.New(core))
	o := iamRoleBuilder(nil, nil, false, false)
	tp := trustPrincipals{aws: []string{"arn:aws:iam::" + testSyncedAcct + ":role/x"}}
	opts := resourceSdk.SyncOpAttrs{SyncID: "sync-1"}

	tc := o.trustGrantContext(ctx, opts, testRoleAcct, tp)
	assert.False(t, tc.isSynced(testSyncedAcct))
	assert.True(t, tc.isSynced(testRoleAcct))
	require.Equal(t, 1, logs.Len())
	assert.Contains(t, logs.All()[0].Message, "synced accounts are not known")

	// A second role in the same sync does not log again.
	o.trustGrantContext(ctx, opts, testRoleAcct, tp)
	assert.Equal(t, 1, logs.Len(), "one fallback log for each sync")

	// A new sync logs again.
	o.trustGrantContext(ctx, resourceSdk.SyncOpAttrs{SyncID: "sync-2"}, testRoleAcct, tp)
	assert.Equal(t, 2, logs.Len())

	ss := newMemorySessionStore()
	rememberSyncedAccounts(ctx, ss, testSyncedAcct)
	tc = o.trustGrantContext(ctx, resourceSdk.SyncOpAttrs{Session: ss, SyncID: "sync-3"}, testRoleAcct, tp)
	assert.True(t, tc.isSynced(testSyncedAcct))
	assert.Equal(t, 2, logs.Len(), "no log when the set is known")
}

func TestSyncSkips_IndependentTotalsPerSync(t *testing.T) {
	core, logs := newLogRecorder()
	ctx := ctxWithLogger(zap.New(core))
	s := &syncSkips{}

	s.forSync("a").record(ctx, skipCounts{Wildcard: 2})
	s.forSync("a").record(ctx, skipCounts{Wildcard: 1})
	assert.Equal(t, skipCounts{Wildcard: 3}, s.forSync("a").totals)
	s.forSync("b").record(ctx, skipCounts{Unsupported: 1})
	assert.Equal(t, skipCounts{Unsupported: 1}, s.forSync("b").totals, "sync b starts from zero")
	// Sync b has its own first Info line.
	last := logs.All()[logs.Len()-1]
	assert.Equal(t, zapcore.InfoLevel, last.Level)
	assert.EqualValues(t, 0, last.ContextMap()[skipWildcard])
	assert.EqualValues(t, 1, last.ContextMap()[skipUnsupported])
	assert.EqualValues(t, 1, last.ContextMap()["roles_seen"])
}

func TestSkipTracker(t *testing.T) {
	core, logs := newLogRecorder()
	ctx := ctxWithLogger(zap.New(core))
	now := time.Unix(1000, 0)
	tr := newSkipTracker()
	tr.now = func() time.Time { return now }

	tr.record(ctx, skipCounts{})
	assert.Equal(t, 0, logs.Len(), "no skips, no log")

	tr.record(ctx, skipCounts{NotSyncedAccount: 2, Wildcard: 1})
	require.Equal(t, 1, logs.Len(), "first skip logs")
	assert.Equal(t, "baton-aws: skipped trust principals", logs.All()[0].Message)

	tr.record(ctx, skipCounts{Unsupported: 1})
	require.Equal(t, 2, logs.Len(), "rate limited at Info, logged at Debug")
	assert.Equal(t, zapcore.DebugLevel, logs.All()[1].Level)
	assert.EqualValues(t, 1, logs.All()[1].ContextMap()[skipUnsupported], "Debug line has the latest totals")

	now = now.Add(skipLogInterval + time.Second)
	tr.record(ctx, skipCounts{NotSyncedAccount: 1})
	require.Equal(t, 3, logs.Len())
	assert.Equal(t, zapcore.InfoLevel, logs.All()[2].Level)
	f := logs.All()[2].ContextMap()
	assert.EqualValues(t, 3, f[skipNotSyncedAccount])
	assert.EqualValues(t, 1, f[skipWildcard])
	assert.EqualValues(t, 1, f[skipUnsupported])
}

func TestRoleAssignmentGrantableTo(t *testing.T) {
	ids := make([]string, 0, len(roleAssignmentGrantableTo))
	for _, rt := range roleAssignmentGrantableTo {
		ids = append(ids, rt.Id)
	}
	assert.Equal(t, []string{resourceTypeIAMUser.Id, resourceTypeRole.Id, resourceTypeIAMGroup.Id, resourceTypeSSOUser.Id}, ids)
}

func ctxWithLogger(l *zap.Logger) context.Context {
	return ctxzap.ToContext(context.Background(), l)
}

func newTestIAMRole(accountID, trustDocument string) iamTypes.Role {
	return iamTypes.Role{
		Arn:                      awsSdk.String("arn:aws:iam::" + accountID + ":role/target"),
		Path:                     awsSdk.String("/"),
		RoleName:                 awsSdk.String("target"),
		AssumeRolePolicyDocument: awsSdk.String(trustDocument),
	}
}

// logRecorder is a minimal zapcore.Core that keeps every entry in memory.
type logRecorder struct {
	mu      *sync.Mutex
	entries *[]recordedEntry
	fields  []zapcore.Field
}

type recordedEntry struct {
	Message string
	Level   zapcore.Level
	fields  []zapcore.Field
}

func (e recordedEntry) ContextMap() map[string]any {
	enc := zapcore.NewMapObjectEncoder()
	for _, f := range e.fields {
		f.AddTo(enc)
	}
	return enc.Fields
}

type recordedLogs struct {
	mu      *sync.Mutex
	entries *[]recordedEntry
}

func (r *recordedLogs) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(*r.entries)
}

func (r *recordedLogs) All() []recordedEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recordedEntry(nil), *r.entries...)
}

func newLogRecorder() (zapcore.Core, *recordedLogs) {
	mu := &sync.Mutex{}
	entries := &[]recordedEntry{}
	return &logRecorder{mu: mu, entries: entries}, &recordedLogs{mu: mu, entries: entries}
}

func (c *logRecorder) Enabled(l zapcore.Level) bool { return l >= zapcore.DebugLevel }
func (c *logRecorder) With(f []zapcore.Field) zapcore.Core {
	return &logRecorder{mu: c.mu, entries: c.entries, fields: append(append([]zapcore.Field(nil), c.fields...), f...)}
}
func (c *logRecorder) Check(e zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(e.Level) {
		return ce.AddCore(e, c)
	}
	return ce
}
func (c *logRecorder) Write(e zapcore.Entry, f []zapcore.Field) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	*c.entries = append(*c.entries, recordedEntry{Message: e.Message, Level: e.Level, fields: append(append([]zapcore.Field(nil), c.fields...), f...)})
	return nil
}
func (c *logRecorder) Sync() error { return nil }
