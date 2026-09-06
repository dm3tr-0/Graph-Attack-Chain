import { NextResponse } from 'next/server';
import { SCENARIOS } from '@/lib/attack-graph-engine';

export async function GET() {
  return NextResponse.json({
    scenarios: SCENARIOS.map(s => ({
      id: s.id,
      name: s.name,
      description: s.description,
      complexity: s.complexity,
      techniques: s.techniques,
    })),
  });
}
