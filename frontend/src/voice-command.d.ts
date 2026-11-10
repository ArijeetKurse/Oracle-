type ConfirmedVoiceResult =
  | { type: 'investigation'; investigation: { id: string }; fallback?: string; provider_error?: string }
  | { type: 'answer'; investigation_id: string; answer: string }
  | { type: 'resource_summary'; summary: string }
  | { type: 'alert'; alert: { title: string; explanation: string } };
export function confirmedVoiceOutcome(result: ConfirmedVoiceResult): { tab: string; investigationId?: string; message: string };
