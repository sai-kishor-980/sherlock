import React, { useEffect } from "react";

export const ThreeBackground: React.FC = () => {
  useEffect(() => {
    const init3D = () => {
      if (typeof (window as any).HMACFR_3DEngine === "function") {
        try {
          if (!(window as any).hmacfr3DInstance) {
            (window as any).hmacfr3DInstance = new (window as any).HMACFR_3DEngine();
          }
        } catch (err) {
          console.warn("3D Engine init:", err);
        }
      }
    };

    if (document.readyState === "complete") {
      init3D();
    } else {
      window.addEventListener("load", init3D);
      const timer = setTimeout(init3D, 500);
      return () => {
        window.removeEventListener("load", init3D);
        clearTimeout(timer);
      };
    }
  }, []);

  return <canvas id="three-bg-canvas" />;
};
