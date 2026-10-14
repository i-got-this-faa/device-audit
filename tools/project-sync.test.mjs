import test from 'node:test';
import assert from 'node:assert/strict';
import {REPOSITORY, references, declaredRelationships, assertComplete,
  buildPlan, applyPlan, readRepository, readProject} from './project-sync.mjs';

const labels = ['area:contracts','kind:Task','lane:Shared','priority:P0','weeks:1-2'];
function connection(nodes) { return {nodes,pageInfo:{hasNextPage:false,endCursor:null}}; }
function issue(number, changes = {}) {
  return {id:`I${number}`,databaseId:1000+number,number,title:`Task ${number}`,
    body:'## Dependencies\n\n- None\n\n## Evidence\n',state:'OPEN',stateReason:null,
    labels:connection(labels.map(name => ({name}))),blockedBy:connection([]),
    subIssues:connection([]),parent:null,repository:{nameWithOwner:REPOSITORY},...changes};
}
function pr(number, body, closing = [], changes = {}) {
  return {id:`PR${number}`,number,body,state:'OPEN',isDraft:false,headRefName:'work',
    labels:connection([]),closingIssuesReferences:connection(closing.map(number => ({number,repository:{nameWithOwner:REPOSITORY}}))),...changes};
}
function project(issues, statuses = {}) {
  const definitions = {Status:['Backlog','Ready','In progress','In review','Blocked','Done'],
    Kind:['Task','Epic','Feature','Spike'],Lane:['Shared','Node'],Area:['contracts','scope'],Priority:['P0','P1']};
  const fields = Object.entries(definitions).map(([name,options]) => ({id:`F${name}`,name,
    options:options.map(value => ({id:`${name}:${value}`,name:value}))}));
  fields.push({id:'FWeek',name:'Week',configuration:{iterations:[{id:'W1',title:'Weeks 1-2: Foundations'}],completedIterations:[]}});
  return {id:'P7',fields:connection(fields),items:issues.map(i => ({id:`ITEM${i.number}`,isArchived:false,
    content:{id:i.id,number:i.number,repository:{nameWithOwner:REPOSITORY}},fieldValues:connection([
      {field:{name:'Status'},optionId:`Status:${statuses[i.number] || 'Ready'}`},
      {field:{name:'Kind'},optionId:'Kind:Task'},{field:{name:'Lane'},optionId:'Lane:Shared'},
      {field:{name:'Area'},optionId:'Area:contracts'},{field:{name:'Priority'},optionId:'Priority:P0'},
      {field:{name:'Week'},iterationId:'W1'},
    ])}))};
}
function plan(issues, prs = [], board = project(issues)) { return buildPlan({issues,pullRequests:prs},board); }

test('unblocked triaged issue is Ready and a matching board is a no-op', () => {
  const result = plan([issue(1)]);
  assert.equal(result.states[1],'Ready');
  assert.deepEqual(result.operations,[]);
});

test('dependency completion promotes Ready; reopening blocks again', () => {
  const first = issue(1), dependency = issue(2);
  first.blockedBy.nodes.push(dependency);
  const board = project([first,dependency],{1:'Blocked'});
  assert.equal(plan([first,dependency],[],board).states[1],'Blocked');
  dependency.state = 'CLOSED'; dependency.stateReason = 'COMPLETED';
  assert.equal(plan([first,dependency],[],board).states[1],'Ready');
  dependency.state = 'OPEN'; dependency.stateReason = 'REOPENED';
  assert.equal(plan([first,dependency],[],project([first,dependency])).states[1],'Blocked');
});

test('a not-planned prerequisite does not satisfy acceptance', () => {
  const first = issue(1), dependency = issue(2,{state:'CLOSED',stateReason:'NOT_PLANNED'});
  first.blockedBy.nodes.push(dependency);
  assert.equal(plan([first,dependency]).states[1],'Blocked');
});

test('open closing PR means In review, a draft means In progress', () => {
  const task = issue(1);
  assert.equal(plan([task],[pr(8,'Closes #1',[1])]).states[1],'In review');
  assert.equal(plan([task],[pr(8,'Closes #1',[1],{isDraft:true})]).states[1],'In progress');
});

test('partial references mean In progress without changing closure or issue state', () => {
  const task = issue(80);
  const result = plan([task],[pr(151,'Refs #80. Telemetry subset only.')]);
  assert.equal(result.states[80],'In progress');
  assert.equal(task.state,'OPEN');
  assert.ok(result.operations.every(op => !['close','merge','reference'].includes(op.kind)));
});

test('a blocked partial task stays Blocked until its prerequisite completes', () => {
  const task = issue(14), dependency = issue(72);
  task.blockedBy.nodes.push(dependency);
  const board = project([task,dependency],{14:'Blocked'});
  assert.equal(plan([task,dependency],[pr(155,'Refs #14 and #72.')],board).states[14],'Blocked');
  dependency.state = 'CLOSED'; dependency.stateReason = 'COMPLETED';
  assert.equal(plan([task,dependency],[pr(155,'Refs #14 and #72.')],board).states[14],'In progress');
});

test('a merged partial PR never marks an open issue Done', () => {
  assert.equal(plan([issue(1)],[pr(8,'Refs #1',[],{state:'MERGED'})]).states[1],'Ready');
});

test('closing and reopening issues follows the current issue state', () => {
  const task = issue(1,{state:'CLOSED',stateReason:'COMPLETED'});
  assert.equal(plan([task]).states[1],'Done');
  task.state = 'OPEN';
  assert.equal(plan([task],[],project([task],{1:'Done'})).states[1],'Ready');
});

test('manual hold beats PR activity and started work is preserved', () => {
  const task = issue(1);
  task.labels.nodes.push({name:'automation:hold'});
  assert.equal(plan([task],[pr(8,'Closes #1',[1])]).states[1],'Blocked');
  task.labels.nodes.pop();
  task.labels.nodes.push({name:'automation:started'});
  assert.equal(plan([task]).states[1],'In progress');
  task.labels.nodes.pop();
  assert.equal(plan([task],[],project([task],{1:'In progress'})).states[1],'In progress');
});

test('new untriaged issues do not enter Ready to pick', () => {
  const task = issue(1,{body:'An untriaged bug'});
  assert.equal(plan([task],[],project([task],{1:'Backlog'})).states[1],'Backlog');
});

test('containers roll up child activity but are never auto-closed', () => {
  const parent = issue(1), child = issue(2,{parent:{number:1},state:'CLOSED',stateReason:'COMPLETED'});
  parent.labels.nodes = [{name:'kind:Epic'}];
  assert.equal(plan([parent,child]).states[1],'In review');
  assert.equal(parent.state,'OPEN');
  child.state = 'OPEN';
  assert.equal(plan([parent,child],[pr(8,'Refs #2')]).states[1],'In progress');
});

test('references recognize intended local syntax, URLs and Markdown', () => {
  assert.deepEqual(references('Refs #14 and #72. Keep #99 open.\nCloses https://github.com/i-got-this-faa/device-audit/issues/22.\nRelates to i-got-this-faa/device-audit#80\nRefs [#3](url)'),[3,14,22,72,80]);
});

test('examples, quotations, other repositories and unclosed fences are ignored', () => {
  assert.deepEqual(references('Refs other/repo#2\n> Refs #3\n`Refs #4`\n<!-- Refs #5 -->\n```md\nCloses #6\n```\n~~~\nRefs #7'),[]);
});

test('branch fallback creates a related reference, never a closing keyword', () => {
  const result = plan([issue(22)],[pr(8,'Change',[],{headRefName:'issue/22-work'})]);
  const op = result.operations.find(op => op.kind === 'reference');
  assert.equal(op.body,'Change\n\nRefs #22.');
  assert.equal(result.states[22],'In progress');
  assert.ok(!/closes/i.test(op.body));
});

test('unknown branches do not invent issue links', () => {
  const result = plan([issue(1)],[pr(8,'Change',[],{headRefName:'issue/999-unknown'})]);
  assert.equal(result.warnings.length,1);
  assert.ok(!result.operations.some(op => op.kind === 'reference'));
});

test('label reconciliation preserves custom labels and removes stale managed labels', () => {
  const pull = pr(8,'Refs #1',[],{labels:connection([{name:'custom'},{name:'area:scope'}])});
  const change = plan([issue(1)],[pull]).operations.find(op => op.kind === 'labels');
  assert.deepEqual(change.remove,['area:scope']);
  assert.deepEqual(change.add,[...labels].sort());
  assert.ok(!change.remove.includes('custom'));
});

test('multiple referenced issues union labels without inventing closing relations', () => {
  const a = issue(1), b = issue(2);
  b.labels.nodes = [{name:'kind:Spike'},{name:'lane:Node'},{name:'area:scope'}];
  const result = plan([a,b],[pr(8,'Refs #1 and #2')]);
  const change = result.operations.find(op => op.kind === 'labels');
  assert.ok(change.add.includes('kind:Task') && change.add.includes('kind:Spike'));
});

test('declared native dependencies and parents are added without removing manual links', () => {
  const first = issue(1,{body:'## Dependencies\n- #2\nParent: #3\n'}), second = issue(2), parent = issue(3);
  const result = plan([first,second,parent]);
  assert.ok(result.operations.some(op => op.kind === 'dependency' && op.number === 1 && op.target === 2));
  assert.ok(result.operations.some(op => op.kind === 'parent' && op.number === 1 && op.target === 3));
  first.blockedBy.nodes.push(second); first.parent = {number:3};
  assert.ok(plan([first,second,parent]).operations.every(op => !['dependency','parent'].includes(op.kind)));
});

test('invalid references, conflicts and cycles stop planning before any write', () => {
  assert.throws(() => plan([issue(1,{body:'## Dependencies\n- #999\n'})]),/Unknown dependency/);
  const a = issue(1), b = issue(2);
  a.blockedBy.nodes.push(b); b.blockedBy.nodes.push(a);
  assert.throws(() => plan([a,b]),/Dependency cycle/);
  assert.throws(() => declaredRelationships(issue(1,{body:'Parent: #2\nParent: #3'})),/Conflicting parents/);
  assert.throws(() => plan([issue(1,{parent:{number:2},body:'Parent: #3'}),issue(2),issue(3)]),/Existing parent conflicts/);
  assert.throws(() => plan([issue(1,{parent:{number:2}}),issue(2,{parent:{number:1}})]),/Parent cycle/);
});

test('missing project options fail closed and archived cards are left alone', () => {
  const task = issue(1), board = project([task]);
  board.fields.nodes[0].options.pop();
  assert.throws(() => plan([task],[],board),/Missing Status option Done/);
  const archived = project([task],{1:'Backlog'});
  archived.items[0].isArchived = true;
  assert.deepEqual(plan([task],[],archived).operations,[]);
});

test('missing cards are added and unrelated custom fields remain untouched', () => {
  const task = issue(1), board = project([task]);
  board.items = [];
  const result = plan([task],[],board);
  assert.equal(result.operations[0].kind,'item');
  assert.equal(result.operations.filter(op => op.kind === 'field').length,6);
  assert.ok(result.operations.every(op => !['Estimate','Size','Requirements','Key'].includes(op.field)));
});

test('partial API connections are rejected', () => {
  assert.throws(() => assertComplete({pageInfo:{hasNextPage:true}},'dependencies'),/incomplete dependencies/);
});

test('external parents and blockers are preserved without local-number collisions', () => {
  const task = issue(1,{parent:{number:2,repository:{nameWithOwner:'other/repository'}}});
  task.blockedBy.nodes.push({number:2,state:'OPEN',repository:{nameWithOwner:'other/repository'}});
  const sameNumber = issue(2);
  assert.equal(plan([task,sameNumber]).states[1],'Blocked');
  assert.equal(plan([task,sameNumber]).states[2],'Ready');
  task.body += '\nParent: #2\n';
  assert.throws(() => plan([task,sameNumber]),/Existing parent conflicts/);
});

test('repository and project readers paginate beyond the first 100 items', () => {
  const cursors = [];
  const api = (path, method, {query,variables}) => {
    assert.equal(path,'graphql'); assert.equal(method,'POST');
    const key = query.includes('pullRequests(first') ? 'pullRequests' : query.includes('issues(first') ? 'issues' : 'project';
    cursors.push([key,variables.after]);
    const page = {nodes:[],pageInfo:{hasNextPage:!variables.after,endCursor:variables.after ? null : 'page-2'}};
    if (key === 'project') return {data:{organization:{projectV2:{id:'P7',fields:connection([]),items:page}}}};
    return {data:{repository:{[key]:page}}};
  };
  readRepository(api); readProject(api);
  assert.deepEqual(cursors,[['issues',null],['issues','page-2'],['pullRequests',null],['pullRequests','page-2'],['project',null],['project','page-2']]);
});

test('apply refuses a repository-only preview and rechecks changed PR descriptions', () => {
  const task = issue(1), pull = pr(8,'original',[],{headRefName:'issue/1-task'});
  const result = plan([task],[pull]);
  assert.throws(() => applyPlan(result,{issues:[task]},null,() => assert.fail('write')),/complete project read/);
  const calls = [];
  assert.throws(() => applyPlan(result,{issues:[task]},project([task]),(path,method='GET') => {
    calls.push(method); return {body:'edited by the author'};
  }),/changed; rerun/);
  assert.deepEqual(calls,['GET']);
});

test('applying the plan converges to a no-op on the next read', () => {
  const task = issue(1), pull = pr(8,'Refs #1');
  const repository = {issues:[task],pullRequests:[pull]};
  const board = project([task],{1:'Backlog'});
  const result = buildPlan(repository,board);
  const api = (path,method,payload) => {
    if (path.endsWith('/labels')) {
      pull.labels.nodes.push(...payload.labels.map(name => ({name})));
      return [];
    }
    assert.equal(path,'graphql');
    const {field,value} = payload.variables;
    const name = board.fields.nodes.find(item => item.id === field).name;
    const old = board.items[0].fieldValues.nodes.find(item => item.field.name === name);
    old.optionId = value.singleSelectOptionId;
    return {data:{updateProjectV2ItemFieldValue:{projectV2Item:{id:'ITEM1'}}}};
  };
  applyPlan(result,repository,board,api);
  assert.deepEqual(buildPlan(repository,board).operations,[]);
});
