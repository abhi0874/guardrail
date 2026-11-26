import "server-only";
import type { Run } from "./lab-cases";
export const labCookie = "recruiter-lab";
export type Visitor = {
  until: number;
  starts: number[];
  busy: boolean;
  runs: Run[];
};
type State = {
  visitors: Map<string, Visitor>;
  active: number;
  starts: number[];
};
const shared = globalThis as typeof globalThis & { recruiterLab?: State };
export const labState: State = (shared.recruiterLab ??= {
  visitors: new Map<string, Visitor>(),
  active: 0,
  starts: [],
});
