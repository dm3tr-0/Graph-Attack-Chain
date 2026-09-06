import { NextRequest, NextResponse } from 'next/server';
import { SCENARIOS, analyzeAlert } from '@/lib/attack-graph-engine';

export async function POST(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const scenario = SCENARIOS.find(s => s.id === id);
    if (!scenario) {
      return NextResponse.json({ error: `Scenario '${id}' not found` }, { status: 404 });
    }

    const result = analyzeAlert(scenario.alert, {
      id: scenario.id,
      name: scenario.name,
      description: scenario.description,
      techniques: scenario.techniques,
    });

    return NextResponse.json(result);
  } catch (e) {
    return NextResponse.json({ error: e instanceof Error ? e.message : 'Unknown error' }, { status: 500 });
  }
}
