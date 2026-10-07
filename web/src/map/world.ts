import { feature, mesh } from 'topojson-client';
import type { Topology, GeometryCollection } from 'topojson-specification';
import type { FeatureCollection, MultiLineString } from 'geojson';
import worldUrl from 'sane-topojson/dist/world_110m.json?url';

export interface WorldGeo {
  land: FeatureCollection;
  borders: MultiLineString;
  lakes: FeatureCollection;
  rivers: FeatureCollection;
}

type WorldTopology = Topology<{
  land: GeometryCollection;
  countries: GeometryCollection;
  lakes: GeometryCollection;
  rivers: GeometryCollection;
}>;

let cached: Promise<WorldGeo> | null = null;

/** Loads the bundled sane-topojson world (110m) with land/borders/lakes/rivers. */
export function loadWorld(): Promise<WorldGeo> {
  if (cached) return cached;
  cached = fetch(worldUrl, { credentials: 'same-origin' })
    .then((r) => {
      if (!r.ok) throw new Error(`world topojson HTTP ${r.status}`);
      return r.json() as Promise<WorldTopology>;
    })
    .then((world) => ({
      land: feature(world, world.objects.land) as FeatureCollection,
      borders: mesh(world, world.objects.countries, (a, b) => a !== b),
      lakes: feature(world, world.objects.lakes) as FeatureCollection,
      rivers: feature(world, world.objects.rivers) as FeatureCollection,
    }));
  cached.catch(() => {
    cached = null; // allow retry
  });
  return cached;
}
