const EARTH_RADIUS_KM = 6371;
const DEG = Math.PI / 180;

/** Haversine great-circle distance in km between two lat/lon points. */
export function haversineKm(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const dLat = (lat2 - lat1) * DEG;
  const dLon = (lon2 - lon1) * DEG;
  const a =
    Math.sin(dLat / 2) ** 2 + Math.cos(lat1 * DEG) * Math.cos(lat2 * DEG) * Math.sin(dLon / 2) ** 2;
  return EARTH_RADIUS_KM * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

/** Same as haversineKm but on [lon, lat] tuples (d3-geo order). */
export function geoDistKm(a: readonly [number, number], b: readonly [number, number]): number {
  return haversineKm(a[1], a[0], b[1], b[0]);
}

/** Half the Earth's circumference — the longest possible great-circle arc. */
export const MAX_GEO_DIST_KM = 20015;

export function hasGeo(lat: number | undefined, lon: number | undefined): boolean {
  return Boolean(lat || lon) && Number.isFinite(lat) && Number.isFinite(lon);
}
