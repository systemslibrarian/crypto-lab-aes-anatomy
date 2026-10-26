import { shiftRows } from './aes/state';

/** Trace labeled bytes, not sampled differences: each source column must
 * disperse to four distinct destination columns for the wide-trail argument. */
export function columnDispersion(weakened = false): number[][] {
  const labels = Uint8Array.from({length: 16}, (_, i) => i);
  const output = weakened ? labels : shiftRows(labels);
  return Array.from({length: 4}, (_, column) =>
    Array.from({length: 4}, (_, row) => Math.floor(output.indexOf(4 * column + row) / 4)));
}
export function dispersesColumns(weakened = false): boolean {
  return columnDispersion(weakened).every(destinations => new Set(destinations).size === 4);
}
