export function confirmedVoiceOutcome(result) {
  if (result?.type === 'investigation' && result.investigation?.id) {
    return { tab: 'Investigations', investigationId: result.investigation.id, message: result.fallback || 'Opened the selected investigation.' };
  }
  if (result?.type === 'answer' && result.investigation_id) {
    return { tab: 'Investigations', investigationId: result.investigation_id, message: result.answer || 'ORACLE reviewed the selected investigation.' };
  }
  if (result?.type === 'resource_summary') {
    return { tab: 'Resources', message: result.summary || 'Historical resource measurements loaded.' };
  }
  if (result?.type === 'alert' && result.alert?.title) {
    return { tab: 'Alerts', message: `${result.alert.title}: ${result.alert.explanation}` };
  }
  throw new Error('ORACLE returned an unsupported voice action.');
}
