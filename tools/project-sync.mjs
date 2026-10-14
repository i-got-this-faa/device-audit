#!/usr/bin/env node
// Metadata only. Never checks out, imports, or runs pull-request code.
import {execFileSync} from 'node:child_process';
import {writeFileSync, appendFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';

export const REPOSITORY = 'i-got-this-faa/device-audit';
export const PROJECT = 7;
const PREFIXES = ['area:', 'kind:', 'lane:', 'priority:', 'weeks:'];
const CONNECTION = 'pageInfo { hasNextPage endCursor }';
const ISSUE_QUERY = `query($owner:String!,$name:String!,$after:String) {
  repository(owner:$owner,name:$name) {
    issues(first:100,after:$after,orderBy:{field:CREATED_AT,direction:ASC}) {
      ${CONNECTION}
      nodes { id databaseId number title body state stateReason
        labels(first:100) { nodes { name } pageInfo { hasNextPage } }
        parent { number repository { nameWithOwner } }
        blockedBy(first:100) { nodes { number state stateReason repository { nameWithOwner } }
          pageInfo { hasNextPage } }
        subIssues(first:100) { nodes { number state repository { nameWithOwner } }
          pageInfo { hasNextPage } }
      }
    }
  }
}`;
const PR_QUERY = `query($owner:String!,$name:String!,$after:String) {
  repository(owner:$owner,name:$name) {
    pullRequests(first:100,after:$after,orderBy:{field:CREATED_AT,direction:ASC}) {
      ${CONNECTION}
      nodes { id number body state isDraft headRefName
        labels(first:100) { nodes { name } pageInfo { hasNextPage } }
        closingIssuesReferences(first:100) {
          nodes { number repository { nameWithOwner } } pageInfo { hasNextPage }
        }
      }
    }
  }
}`;
const PROJECT_QUERY = `query($owner:String!,$number:Int!,$after:String) {
  organization(login:$owner) { projectV2(number:$number) {
    id
    fields(first:100) { pageInfo { hasNextPage } nodes {
      ... on ProjectV2Field { id name }
      ... on ProjectV2SingleSelectField { id name options { id name } }
      ... on ProjectV2IterationField { id name configuration {
        iterations { id title } completedIterations { id title }
      } }
    } }
    items(first:100,after:$after) { ${CONNECTION} nodes {
      id isArchived content { ... on Issue { id number repository { nameWithOwner } } }
      fieldValues(first:100) { pageInfo { hasNextPage } nodes {
        ... on ProjectV2ItemFieldSingleSelectValue {
          optionId field { ... on ProjectV2SingleSelectField { name } }
        }
        ... on ProjectV2ItemFieldIterationValue {
          iterationId field { ... on ProjectV2IterationField { name } }
        }
      } }
    } }
  } }
}`;

export function gh(path, method = 'GET', payload) {
  const args = ['api', path, '--method', method];
  if (payload !== undefined) args.push('--input', '-');
  try {
    const out = execFileSync('gh', args, {encoding:'utf8',
      input:payload === undefined ? undefined : JSON.stringify(payload),
      stdio:['pipe','pipe','pipe'], maxBuffer:32 * 1024 * 1024});
    const result = out.trim() ? JSON.parse(out) : null;
    if (result?.errors) throw new Error(JSON.stringify(result.errors));
    return result;
  } catch (error) {
    throw new Error(`GitHub request failed (${method} ${path}): ${String(error.stderr || error.message).slice(0,800)}`);
  }
}

function graphql(api, query, variables) {
  return api('graphql', 'POST', {query, variables}).data;
}

export function assertComplete(connection, label) {
  if (connection?.pageInfo?.hasNextPage) throw new Error(`Refusing incomplete ${label}`);
}

export function readRepository(api = gh) {
  const [owner, name] = REPOSITORY.split('/');
  const data = {};
  for (const [key, query] of [['issues',ISSUE_QUERY], ['pullRequests',PR_QUERY]]) {
    data[key] = [];
    let after = null;
    do {
      const page = graphql(api, query, {owner,name,after}).repository[key];
      for (const item of page.nodes) {
        for (const field of ['labels','blockedBy','subIssues','closingIssuesReferences']) {
          if (item[field]) assertComplete(item[field], `${key} #${item.number} ${field}`);
        }
      }
      data[key].push(...page.nodes);
      after = page.pageInfo.hasNextPage ? page.pageInfo.endCursor : null;
      if (page.pageInfo.hasNextPage && !after) throw new Error('Missing repository pagination cursor');
    } while (after);
  }
  return data;
}

export function readProject(api = gh) {
  let project;
  let after = null;
  const items = [];
  do {
    const page = graphql(api, PROJECT_QUERY, {owner:REPOSITORY.split('/')[0],number:PROJECT,after})
      .organization?.projectV2;
    if (!page) throw new Error('Project 7 is inaccessible; check the Projects credential');
    assertComplete(page.fields, 'project fields');
    for (const item of page.items.nodes) assertComplete(item.fieldValues, 'project item field values');
    project = page;
    items.push(...page.items.nodes);
    after = page.items.pageInfo.hasNextPage ? page.items.pageInfo.endCursor : null;
    if (page.items.pageInfo.hasNextPage && !after) throw new Error('Missing project pagination cursor');
  } while (after);
  return {...project, items};
}

export function prose(body = '') {
  let fence;
  return body.replace(/<!--[\s\S]*?-->/g,'').split('\n').filter(line => {
    const marker = line.match(/^\s*(`{3,}|~{3,})/);
    if (fence) {
      if (marker && marker[1][0] === fence[0] && marker[1].length >= fence.length) fence = undefined;
      return false;
    }
    if (marker) { fence = marker[1]; return false; }
    return true;
  }).join('\n').replace(/`[^`\n]*`/g,'');
}

export function references(body = '') {
  const result = new Set();
  const text = prose(body);
  for (const line of text.split('\n').filter(line => !/^\s*>/.test(line))) {
    const match = line.match(/\b(?:refs?|references?|relates? to|closes?|fix(?:es|ed)?|resolves?)\s+(.+)/i);
    if (!match) continue;
    const targets = match[1].split(/\.(?=\s|$)/)[0];
    // A bare #N must not be the suffix of another repository's reference or URL.
    for (const ref of targets.matchAll(/(?:^|[\s,(\[])#(\d+)\b/g)) result.add(Number(ref[1]));
    for (const ref of targets.matchAll(/https:\/\/github\.com\/i-got-this-faa\/device-audit\/issues\/(\d+)\b/g)) {
      result.add(Number(ref[1]));
    }
    for (const ref of targets.matchAll(/(?:^|[\s,(])i-got-this-faa\/device-audit#(\d+)\b/g)) result.add(Number(ref[1]));
  }
  return [...result].sort((a,b) => a-b);
}

export function declaredRelationships(issue) {
  const text = prose(issue.body);
  const section = text.match(/^## Dependencies\s*\n([\s\S]*?)(?=^## |^Parent:|$(?![\s\S]))/m);
  const dependencies = [...new Set([...(section?.[1] || '').matchAll(/^\s*-\s+#(\d+)\b/gm)]
    .map(match => Number(match[1])))];
  const parents = [...text.matchAll(/^Parent:\s*#(\d+)\s*$/gm)].map(match => Number(match[1]));
  if (new Set(parents).size > 1) throw new Error(`Conflicting parents for #${issue.number}`);
  return {dependencies, parent:parents[0], triaged:Boolean(section)};
}

function names(issue) { return issue.labels.nodes.map(label => label.name); }
function local(node) { return node.repository.nameWithOwner.toLowerCase() === REPOSITORY; }
function fieldValue(item, name) { return item?.fieldValues.nodes.find(value => value.field?.name === name); }

function assertAcyclic(graph, label) {
  const done = new Set();
  const path = new Set();
  function visit(number) {
    if (path.has(number)) throw new Error(`${label} cycle at #${number}`);
    if (done.has(number)) return;
    path.add(number);
    for (const child of graph.get(number) || []) visit(child);
    path.delete(number);
    done.add(number);
  }
  for (const number of graph.keys()) visit(number);
}

export function buildPlan(repository, project) {
  const issues = new Map(repository.issues.map(issue => [issue.number,issue]));
  const items = new Map();
  if (project) for (const item of project.items) {
    if (item.content?.repository && local(item.content)) {
      if (items.has(item.content.number)) throw new Error(`Duplicate project item #${item.content.number}`);
      items.set(item.content.number,item);
    }
  }
  const operations = [];
  const warnings = [];
  const deps = new Map();
  const parents = new Map();
  const triaged = new Map();
  for (const issue of issues.values()) {
    const declared = declaredRelationships(issue);
    triaged.set(issue.number,declared.triaged);
    const existing = issue.blockedBy.nodes;
    const merged = [...existing];
    for (const dependency of declared.dependencies) {
      if (!issues.has(dependency)) throw new Error(`Unknown dependency #${dependency} on #${issue.number}`);
      if (!existing.some(node => local(node) && node.number === dependency)) {
        merged.push({...issues.get(dependency),repository:{nameWithOwner:REPOSITORY}});
        operations.push({kind:'dependency',number:issue.number,target:dependency});
      }
    }
    deps.set(issue.number,merged);
    if (declared.parent && !issues.has(declared.parent)) throw new Error(`Unknown parent on #${issue.number}`);
    const externalParent = issue.parent?.repository && !local(issue.parent);
    if (declared.parent && issue.parent && (externalParent || issue.parent.number !== declared.parent)) {
      throw new Error(`Existing parent conflicts with declaration on #${issue.number}`);
    }
    const parent = declared.parent || (!externalParent && issue.parent?.number);
    if (parent) parents.set(issue.number,parent);
    if (declared.parent && !issue.parent) operations.push({kind:'parent',number:issue.number,target:declared.parent});
  }
  assertAcyclic(new Map([...deps].map(([number,nodes]) => [number,nodes.filter(local).map(node => node.number)])), 'Dependency');
  assertAcyclic(new Map([...parents].map(([child,parent]) => [child,[parent]])), 'Parent');
  const activity = new Map();
  for (const pr of repository.pullRequests) {
    const closing = pr.closingIssuesReferences.nodes.filter(local).map(node => node.number);
    let refs = [...new Set([...references(pr.body), ...closing])];
    const branchIssue = pr.headRefName.match(/^issue\/(\d+)(?:[-_/]|$)/)?.[1];
    if (!refs.length && branchIssue && issues.has(Number(branchIssue)) && pr.state === 'OPEN') {
      refs = [Number(branchIssue)];
      operations.push({kind:'reference',number:pr.number,issue:refs[0],
        oldBody:pr.body || '',body:`${pr.body || ''}\n\nRefs #${refs[0]}.`});
    }
    const known = refs.filter(number => issues.has(number));
    if (pr.state === 'OPEN' && !known.length) warnings.push(`PR #${pr.number}: add Closes #N (complete scope) or Refs #N (partial scope)`);
    const desiredLabels = [...new Set(known.flatMap(number => names(issues.get(number)))
      .filter(name => PREFIXES.some(prefix => name.startsWith(prefix))))].sort();
    const oldLabels = names(pr);
    if (known.length) {
      const add = desiredLabels.filter(label => !oldLabels.includes(label));
      const remove = oldLabels.filter(label => PREFIXES.some(prefix => label.startsWith(prefix)) && !desiredLabels.includes(label));
      if (add.length || remove.length) operations.push({kind:'labels',number:pr.number,add,remove});
    }
    if (pr.state === 'OPEN') for (const number of known) {
      const previous = activity.get(number);
      const next = closing.includes(number) && !pr.isDraft ? 'In review' : 'In progress';
      activity.set(number,previous === 'In review' ? previous : next);
    }
  }
  const states = new Map();
  function status(number) {
    if (states.has(number)) return states.get(number);
    const issue = issues.get(number);
    const labels = names(issue);
    const item = items.get(number);
    const currentOption = fieldValue(item,'Status')?.optionId;
    const current = project?.fields.nodes.find(field => field.name === 'Status')?.options
      .find(option => option.id === currentOption)?.name;
    const children = [...parents].filter(([,parent]) => parent === number).map(([child]) => child);
    // Preserve cross-repository children in container progress without importing their code/data.
    const externalChildren = issue.subIssues.nodes.filter(node => !local(node));
    const blocked = deps.get(number).some(dependency => dependency.state !== 'CLOSED' || dependency.stateReason !== 'COMPLETED');
    let next;
    if (issue.state === 'CLOSED') next = 'Done';
    else if (labels.includes('automation:hold')) next = 'Blocked';
    else if (activity.get(number) === 'In review') next = 'In review';
    else if (current === 'Blocked' && blocked) next = 'Blocked';
    else if (activity.has(number)) next = activity.get(number);
    else if (labels.includes('automation:started') || current === 'In progress') next = 'In progress';
    else if (children.length || externalChildren.length) {
      const childStates = children.map(status);
      const allDone = childStates.every(state => state === 'Done') && externalChildren.every(child => child.state === 'CLOSED');
      next = allDone ? 'In review' : childStates.some(state => ['In progress','In review','Done'].includes(state)) ? 'In progress' : blocked ? 'Blocked' : 'Backlog';
    } else if (blocked) next = 'Blocked';
    else if (labels.some(label => ['kind:Epic','kind:Feature'].includes(label))) next = 'Backlog';
    else next = triaged.get(number) || current === 'Ready' ? 'Ready' : 'Backlog';
    states.set(number,next);
    return next;
  }
  for (const number of issues.keys()) status(number);
  if (project) {
    const fields = new Map(project.fields.nodes.map(field => [field.name,field]));
    const statusField = fields.get('Status');
    for (const name of ['Backlog','Ready','In progress','In review','Blocked','Done']) {
      if (!statusField?.options?.some(option => option.name === name)) throw new Error(`Missing Status option ${name}`);
    }
    for (const issue of issues.values()) {
      const item = items.get(issue.number);
      // Do not resurrect intentionally archived work.
      if (item?.isArchived) continue;
      if (!item) operations.push({kind:'item',number:issue.number});
      const values = [['Status',{singleSelectOptionId:statusField.options.find(option => option.name === states.get(issue.number)).id}]];
      for (const [prefix,fieldName] of [['kind:','Kind'],['lane:','Lane'],['area:','Area'],['priority:','Priority']]) {
        const matches = names(issue).filter(name => name.startsWith(prefix));
        if (matches.length > 1) throw new Error(`Conflicting ${prefix} labels on #${issue.number}`);
        if (!matches.length) continue;
        const field = fields.get(fieldName);
        const option = field?.options?.find(option => option.name === matches[0].slice(prefix.length));
        if (!option) throw new Error(`Missing ${fieldName} option for #${issue.number}`);
        values.push([fieldName,{singleSelectOptionId:option.id}]);
      }
      const weeks = names(issue).filter(name => name.startsWith('weeks:'));
      if (weeks.length > 1) throw new Error(`Conflicting weeks labels on #${issue.number}`);
      if (weeks.length) {
        const field = fields.get('Week');
        const iterations = [...(field?.configuration?.iterations || []),...(field?.configuration?.completedIterations || [])];
        const iteration = iterations.find(value => value.title.startsWith(`Weeks ${weeks[0].slice(6)}:`));
        if (!iteration) throw new Error(`Missing Week iteration for #${issue.number}`);
        values.push(['Week',{iterationId:iteration.id}]);
      }
      for (const [fieldName,value] of values) {
        const old = fieldValue(item,fieldName);
        if ((value.singleSelectOptionId && old?.optionId === value.singleSelectOptionId) ||
            (value.iterationId && old?.iterationId === value.iterationId)) continue;
        operations.push({kind:'field',number:issue.number,fieldId:fields.get(fieldName).id,field:fieldName,value});
      }
    }
  }
  return {repository:REPOSITORY,project:PROJECT,projectVerified:Boolean(project),
    states:Object.fromEntries([...states].sort(([a],[b]) => a-b)),warnings,operations};
}

export function applyPlan(plan, repository, project, api = gh) {
  if (!project || !plan.projectVerified) throw new Error('Apply requires a complete project read');
  const issues = new Map(repository.issues.map(issue => [issue.number,issue]));
  const ids = new Map(project.items.filter(item => item.content?.repository && local(item.content))
    .map(item => [item.content.number,item.id]));
  for (const op of plan.operations) {
    const path = `repos/${REPOSITORY}/issues/${op.number}`;
    if (op.kind === 'dependency') api(`${path}/dependencies/blocked_by`,'POST',{issue_id:issues.get(op.target).databaseId});
    else if (op.kind === 'parent') api(`repos/${REPOSITORY}/issues/${op.target}/sub_issues`,'POST',{sub_issue_id:issues.get(op.number).databaseId});
    else if (op.kind === 'reference') {
      const latest = api(`repos/${REPOSITORY}/pulls/${op.number}`);
      if ((latest.body || '') !== op.oldBody) throw new Error(`PR #${op.number} changed; rerun before adding its reference`);
      api(`repos/${REPOSITORY}/pulls/${op.number}`,'PATCH',{body:op.body});
    }
    else if (op.kind === 'labels') {
      if (op.add.length) api(`${path}/labels`,'POST',{labels:op.add});
      for (const label of op.remove) api(`${path}/labels/${encodeURIComponent(label)}`,'DELETE');
    } else if (op.kind === 'item') {
      const data = graphql(api,`mutation($project:ID!,$content:ID!) {
        addProjectV2ItemById(input:{projectId:$project,contentId:$content}) { item { id } }
      }`,{project:project.id,content:issues.get(op.number).id});
      ids.set(op.number,data.addProjectV2ItemById.item.id);
    } else if (op.kind === 'field') {
      graphql(api,`mutation($project:ID!,$item:ID!,$field:ID!,$value:ProjectV2FieldValue!) {
        updateProjectV2ItemFieldValue(input:{projectId:$project,itemId:$item,fieldId:$field,value:$value}) {
          projectV2Item { id }
        }
      }`,{project:project.id,item:ids.get(op.number),field:op.fieldId,value:op.value});
    } else throw new Error(`Unknown operation ${op.kind}`);
  }
}

export function main(args = process.argv.slice(2)) {
  const allowed = new Set(['--apply','--repository-only','--output']);
  for (let i = 0; i < args.length; i++) {
    if (!allowed.has(args[i])) throw new Error(`Unknown argument ${args[i]}`);
    if (args[i] === '--output') { if (!args[++i]) throw new Error('Missing output path'); }
  }
  if (args.includes('--apply') && args.includes('--repository-only')) throw new Error('Repository-only mode is read-only');
  const repository = readRepository();
  const project = args.includes('--repository-only') ? null : readProject();
  const plan = buildPlan(repository,project);
  const output = args.includes('--output') ? args[args.indexOf('--output') + 1] : undefined;
  // Avoid copying whole PR bodies into logs or run artifacts.
  const report = {...plan,applied:false,verified:false,
    operations:plan.operations.map(({body,oldBody,...op}) => op)};
  const json = JSON.stringify(report,null,2) + '\n';
  if (output) writeFileSync(output,json);
  console.log(json);
  if (args.includes('--apply')) {
    applyPlan(plan,repository,project);
    const remaining = buildPlan(readRepository(),readProject());
    report.applied = true;
    report.verified = remaining.operations.length === 0;
    report.remaining = remaining.operations.map(({body,oldBody,...op}) => op);
    if (output) writeFileSync(output,JSON.stringify(report,null,2) + '\n');
    if (!report.verified) throw new Error('Read-back found remaining changes; inspect the plan and rerun');
    console.log('PASS: GitHub read-back reproduced the plan with zero remaining writes.');
  }
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY,
    `## Project 7 reconciliation\n\nMode: ${args.includes('--apply') ? 'applied' : 'dry run'}. ${plan.operations.length} operation(s).\n\n` +
    Object.entries(plan.states).map(([number,state]) => `- #${number}: ${state}`).join('\n') +
    '\n\n' + plan.warnings.map(warning => `- ${warning}`).join('\n') + '\n');
  return plan;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; }
}
