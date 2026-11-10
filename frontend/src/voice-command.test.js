import assert from 'node:assert/strict';
import test from 'node:test';
import { confirmedVoiceOutcome } from './voice-command.js';

test('confirmed investigation response opens that case',()=>{
  assert.deepEqual(confirmedVoiceOutcome({type:'investigation',investigation:{id:'case-1'}}),{tab:'Investigations',investigationId:'case-1',message:'Opened the selected investigation.'});
});

test('historical result reports the measured summary',()=>{
  assert.deepEqual(confirmedVoiceOutcome({type:'resource_summary',summary:'12 recorded samples.'}),{tab:'Resources',message:'12 recorded samples.'});
});

test('investigation explanation keeps the answer attached to its case',()=>{
  assert.deepEqual(confirmedVoiceOutcome({type:'answer',investigation_id:'case-2',answer:'Memory rose after 10:04.'}),{tab:'Investigations',investigationId:'case-2',message:'Memory rose after 10:04.'});
});

test('alert result shows a grounded alert explanation',()=>{
  assert.deepEqual(confirmedVoiceOutcome({type:'alert',alert:{title:'worker memory growth',explanation:'RSS rose above baseline.'}}),{tab:'Alerts',message:'worker memory growth: RSS rose above baseline.'});
});

test('unknown actions are rejected',()=>{
  assert.throws(()=>confirmedVoiceOutcome({type:'shell',command:'no'}),/unsupported voice action/);
});
