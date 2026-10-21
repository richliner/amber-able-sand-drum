import { createFileRoute } from "@tanstack/react-router";
import { Laptop, Puzzle } from "lucide-react";
import { DesktopApp } from "@/components/ironclad/desktop";
import { ExtensionStudio } from "@/components/ironclad/studio";
import { AlertPump, PersistBridge, ToastStack } from "@/components/ironclad/ui";
import { useIronclad, type Surface } from "@/lib/ironclad/store";

export const Route = createFileRoute("/")({
  component: Home,
});

function Segmented() {
  const surface = useIronclad((s) => s.surface);
  const setSurface = useIronclad((s) => s.setSurface);
  const items: { id: Surface; label: string; icon: typeof Laptop }[] = [
    { id: "software", label: "Software", icon: Laptop },
    { id: "extension", label: "Extension", icon: Puzzle },
  ];
  return (
    <div className="seg" role="tablist" aria-label="Surface">
      {items.map((item) => {
        const Icon = item.icon;
        return (
          <button
            key={item.id}
            type="button"
            role="tab"
            aria-selected={surface === item.id}
            onClick={() => setSurface(item.id)}
          >
            <Icon size={16} aria-hidden />
            {item.label}
          </button>
        );
      })}
    </div>
  );
}

function Home() {
  const surface = useIronclad((s) => s.surface);
  return (
    <div className="wallpaper">
      <AlertPump />
      <PersistBridge />
      <ToastStack />
      <div className="stage">
        <header className="topbar">
          <div className="brand-inline">
            <img src="/favicon.svg" alt="" width={40} height={40} />
            <div>
              <p className="eyebrow">IronClad</p>
              <h1>Liquid glass protection</h1>
            </div>
          </div>
          <Segmented />
        </header>
        {surface === "software" ? <DesktopApp /> : <ExtensionStudio />}
      </div>
    </div>
  );
}
