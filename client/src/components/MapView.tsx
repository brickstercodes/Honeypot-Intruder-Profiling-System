import { useEffect, useState } from "react";
import { IntrusionLog } from "@/types";
import { MapView as GoogleMapView } from "@/components/Map";

interface MapViewProps {
  intrusions: IntrusionLog[];
}

export default function MapView({ intrusions }: MapViewProps) {
  const [markers, setMarkers] = useState<any[]>([]);

  useEffect(() => {
    // Prepare markers data for the map
    const markerData = intrusions
      .filter((intrusion) => intrusion.latitude && intrusion.longitude)
      .map((intrusion) => {
        const lat = parseFloat(intrusion.latitude || "0");
        const lng = parseFloat(intrusion.longitude || "0");

        const threatColor =
          intrusion.threatLevel === "critical"
            ? "#ef4444"
            : intrusion.threatLevel === "high"
              ? "#f97316"
              : intrusion.threatLevel === "medium"
                ? "#eab308"
                : "#22c55e";

        return {
          position: { lat, lng },
          title: `${intrusion.ip} - ${intrusion.country || "Unknown"}`,
          threatLevel: intrusion.threatLevel,
          color: threatColor,
        };
      });

    setMarkers(markerData);
  }, [intrusions]);

  const handleMapReady = (map: any) => {
    if (!map || markers.length === 0) return;

    // Add markers to the map
    markers.forEach((marker) => {
      new window.google.maps.Marker({
        position: marker.position,
        map,
        title: marker.title,
        icon: {
          path: window.google.maps.SymbolPath.CIRCLE,
          scale: 8,
          fillColor: marker.color,
          fillOpacity: 0.8,
          strokeColor: "#fff",
          strokeWeight: 2,
        },
      });
    });

    // Fit bounds to show all markers
    if (markers.length > 0) {
      const bounds = new window.google.maps.LatLngBounds();
      markers.forEach((marker) => {
        bounds.extend(marker.position);
      });
      map.fitBounds(bounds);
    }
  };

  return (
    <div className="w-full space-y-4">
      <GoogleMapView
        onMapReady={handleMapReady}
        initialZoom={2}
        initialCenter={{ lat: 20, lng: 0 }}
      />
      <div className="text-sm text-muted-foreground">
        <p>Map shows {intrusions.length} intrusion locations</p>
        <div className="flex gap-4 mt-2 flex-wrap">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full" style={{ backgroundColor: "#ef4444" }} />
            <span>Critical</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full" style={{ backgroundColor: "#f97316" }} />
            <span>High</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full" style={{ backgroundColor: "#eab308" }} />
            <span>Medium</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full" style={{ backgroundColor: "#22c55e" }} />
            <span>Low</span>
          </div>
        </div>
      </div>
    </div>
  );
}
