# TRACEWEAVER: file-role=policy-browser-contract; req=REQ-AUTOADVANCE-008; trace=TRACE-AUTOADVANCE-008; ver=VER-AUTOADVANCE-008
# TRACEWEAVER: verifies=VER-AUTOADVANCE-008; req=REQ-AUTOADVANCE-008; trace=TRACE-AUTOADVANCE-008
# TRACEWEAVER: file-role=policy-browser-contract; req=REQ-AUTOADVANCE-008; trace=TRACE-AUTOADVANCE-008; ver=VER-AUTOADVANCE-008
"""Run the actual page's policy action in Node; synthetic transport, no LTX calls."""
import json
from pathlib import Path
import re
import subprocess


def test_policy_action_uses_displayed_identity_and_never_calls_install():
    page = (Path(__file__).resolve().parents[1] / 'landing-page/index.html').read_text()
    script = '\n'.join(re.findall(r'<script[^>]*>(.*?)</script>',page,re.S))
    # Browser bootstrap does not run in this DOM fixture; call the actual public action.
    fixture = r'''
const assert = require('assert'); const calls=[];
const nodes = new Map();
function node(){return {innerHTML:'',textContent:'',disabled:false,value:'main',hidden:false,
style:{},dataset:{},appendChild(){},append(){},replaceChildren(){},remove(){},after(){},
addEventListener(){},querySelector(){return node()},querySelectorAll(){return []}}}
global.document={getElementById(id){if(!nodes.has(id))nodes.set(id,node());return nodes.get(id)},
querySelector(){return node()},querySelectorAll(){return []},createElement:node,addEventListener(){}};
global.window={addEventListener(){},location:{origin:'http://fixture.test'}};
global.localStorage={getItem(){return null},setItem(){},removeItem(){}};
global.setInterval=()=>0;global.setTimeout=()=>0;global.clearTimeout=()=>{};
global.fetch=async(path,options={})=>{calls.push([path,options.body ? JSON.parse(options.body):null]);
return {ok:true,json:async()=>path.includes('session') ? {csrf_token:'fixture-token'} : {
selection_id:'displayed-release',selection_sha256:'a'.repeat(64),components:{'ipmi-monitor':{mode:'follow-stable',supported:true,installed_release:'1.4.0',selected_release:'1.4.0'}}}}};
'''
    check = r'''
(async()=>{await loadReleasePolicies();await setReleasePolicy('ipmi-monitor','follow-stable');
const request=calls.find(x=>x[0]==='/api/releases/policy-set');assert(request);
assert.deepEqual(request[1],{component:'ipmi-monitor',mode:'follow-stable',expected_selection_id:'displayed-release',expected_selection_sha256:'a'.repeat(64)});
assert(!calls.some(x=>x[0]==='/api/update'||x[0]==='/api/releases/apply'));
console.log('policy action bound to displayed selection; no install');})().catch(e=>{console.error(e);process.exitCode=1});
'''
    result = subprocess.run(['node'],input=fixture+script+check,text=True,capture_output=True)
    assert result.returncode == 0, result.stderr


def test_check_updates_refreshes_policy_before_discovery_and_does_not_install():
    page=(Path(__file__).resolve().parents[1]/'landing-page/index.html').read_text()
    assert 'onclick="checkForUpdates()"' in page
    # A focused real-function execution avoids stubbing the rest of the dashboard.
    start=page.index('async function checkForUpdates()')
    function=page[start:page.index('\n        async function updateService',start)]
    script=r'''
const assert=require('assert');const calls=[];
async function refreshReleasePolicies(){calls.push('advance')}
async function loadVersions(){calls.push('versions')}
async function loadReleaseCandidates(){calls.push('discovery')}
async function startUpdateJob(action,service){calls.push([action,service])}
function showUpdateStatus(){throw Error('unexpected failure')}
'''+function+r'''
(async()=>{await checkForUpdates();assert.deepEqual(calls,['advance','versions','discovery'])})().catch(e=>{console.error(e);process.exitCode=1});
'''
    result=subprocess.run(['node'],input=script,text=True,capture_output=True)
    assert result.returncode==0,result.stderr


def test_selected_pinned_service_is_not_misreported_as_managed_separately():
    from tests.test_latest_status import landing_script
    script=landing_script()+r'''
loadWatchdogStatus=()=>{};const grid={innerHTML:''};
global.document={getElementById:id=>id==='versionsGrid'?grid:id==='targetBranch'?{value:'main'}:null,
querySelector:()=>({style:{}})};
global.fetch=async()=>({ok:true,json:async()=>({'ipmi-monitor':{running:true,version:'1.4.0',selected_release:'1.4.0',selected_channel:'main',pinned:true,update_available:false}})});
loadVersions().then(()=>{if(grid.innerHTML.includes('managed separately')||!grid.innerHTML.includes('Selected release installed'))process.exitCode=1});
'''
    result=subprocess.run(['node'],input=script,text=True,capture_output=True)
    assert result.returncode==0,result.stderr
