import { reportToPdf } from "@/lib/export/pdf";
import { cachedPdf, exportableReport, fileResponse, fontDir, loadScreenshots, requestOrigin } from "@/lib/export/serve";
import { jsonError } from "@/lib/request";

/** The finished report as a PDF, screenshots embedded. */
export async function GET(req: Request, ctx: RouteContext<"/api/audits/[id]/report.pdf">) {
  const { id } = await ctx.params;
  const report = await exportableReport(req, id);
  if (report instanceof Response) return report;
  const origin = requestOrigin(req);
  try {
    const pdf = await cachedPdf(`${report.auditId}:${report.finishedAt}:${origin}`, async () =>
      reportToPdf(report, { origin, fontDir: fontDir(), images: await loadScreenshots(report) }),
    );
    if (!pdf) return jsonError(503, "busy making other PDFs, try again in a few seconds", { "retry-after": "5" });
    return fileResponse(pdf, report, "pdf");
  } catch (err) {
    console.error("pdf export failed", id, err);
    return jsonError(500, "could not make the PDF");
  }
}
