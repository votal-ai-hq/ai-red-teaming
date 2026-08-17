import { Info } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  FINDING_SEVERITY_METHODOLOGY,
  SCORE_BANDS,
  SCORE_METHODOLOGY,
} from "@/lib/score-methodology";

export function MethodologyInfo({
  topic = "both",
  label = "How this is calculated",
}: {
  topic?: "score" | "severity" | "both";
  label?: string;
}) {
  return (
    <Dialog>
      <DialogTrigger
        className="inline-flex items-center justify-center rounded-full p-0.5 text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/30"
        aria-label={label}
        title={label}
      >
        <Info className="w-3.5 h-3.5" />
      </DialogTrigger>
      <DialogContent className="sm:max-w-lg max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Scoring & severity methodology</DialogTitle>
          <DialogDescription>
            How CART turns attack outcomes into a score and Critical / High labels.
          </DialogDescription>
        </DialogHeader>
        {(topic === "score" || topic === "both") && (
          <section className="space-y-2">
            <h3 className="text-sm font-semibold text-foreground">
              {SCORE_METHODOLOGY.title}
            </h3>
            <p className="text-xs font-mono bg-muted/60 rounded-md px-2 py-1.5 text-foreground">
              {SCORE_METHODOLOGY.formula}
            </p>
            <ul className="list-disc pl-4 space-y-1 text-xs text-muted-foreground">
              {SCORE_METHODOLOGY.bullets.map((b) => (
                <li key={b}>{b}</li>
              ))}
            </ul>
            <div className="grid grid-cols-2 gap-2 pt-1">
              {SCORE_BANDS.map((b) => (
                <div
                  key={b.band}
                  className="rounded-md border border-border px-2 py-1.5"
                >
                  <div className="text-xs font-semibold text-foreground">
                    {b.label}{" "}
                    <span className="font-normal text-muted-foreground">
                      {b.min}–{b.max}
                    </span>
                  </div>
                  <p className="text-[11px] text-muted-foreground mt-0.5">
                    {b.meaning}
                  </p>
                </div>
              ))}
            </div>
          </section>
        )}
        {(topic === "severity" || topic === "both") && (
          <section className="space-y-2">
            <h3 className="text-sm font-semibold text-foreground">
              {FINDING_SEVERITY_METHODOLOGY.title}
            </h3>
            <ul className="list-disc pl-4 space-y-1 text-xs text-muted-foreground">
              {FINDING_SEVERITY_METHODOLOGY.bullets.map((b) => (
                <li key={b}>{b}</li>
              ))}
            </ul>
          </section>
        )}
      </DialogContent>
    </Dialog>
  );
}
