import { Lab } from "../../components/lab";
import { labEnabled } from "../../lib/lab-runner";
export const dynamic = "force-dynamic";
export default function Page() {
  return <Lab scanner={true} enabled={labEnabled()} />;
}
