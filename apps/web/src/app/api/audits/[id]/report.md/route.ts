import { reportToMarkdown } from "@/lib/export/markdown";
import { exportableReport, fileResponse, requestOrigin } from "@/lib/export/serve";

/** The finished report as Markdown (for coding agents, or to keep). */
export async function GET(req: Request, ctx: RouteContext<"/api/audits/[id]/report.md">) {
  const { id } = await ctx.params;
  const report = await exportableReport(req, id);
  if (report instanceof Response) return report;
  return fileResponse(reportToMarkdown(report, { origin: requestOrigin(req) }), report, "md");
}
