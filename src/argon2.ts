/**
 * Argon2d and Argon2id, implemented per
 * [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106). See SPEC.md.
 *
 * This module holds the algorithm core; the public, validated entry points
 * live in `index.ts`. The 64-bit arithmetic uses `bigint` for correctness.
 */

import { blake2b } from './blake2b.ts';

const M32 = 0xffffffffn;
const M64 = (1n << 64n) - 1n;

/** Argon2 type code: 0 = Argon2d, 2 = Argon2id (RFC 9106, Section 3.1). */
export const ARGON2_D = 0;
export const ARGON2_ID = 2;

/** Argon2 version numbers (RFC 9106). 0x13 (19) is current. */
export const ARGON2_VERSION_10 = 0x10;
export const ARGON2_VERSION_13 = 0x13;

const SYNC_POINTS = 4; // number of vertical slices (SL)
const WORDS_PER_BLOCK = 128; // 1024 bytes / 8
const ADDRESSES_PER_BLOCK = 128;

export interface CoreParams {
  password: Uint8Array;
  salt: Uint8Array;
  secret: Uint8Array;
  associatedData: Uint8Array;
  parallelism: number;
  /** Memory size in KiB. */
  memory: number;
  iterations: number;
  tagLength: number;
  version: number;
  /** 0 for Argon2d, 2 for Argon2id. */
  type: number;
}

function rotr64(x: bigint, n: bigint): bigint {
  return ((x >> n) | (x << (64n - n))) & M64;
}

function le32(n: number): Uint8Array {
  const out = new Uint8Array(4);
  out[0] = n & 0xff;
  out[1] = (n >>> 8) & 0xff;
  out[2] = (n >>> 16) & 0xff;
  out[3] = (n >>> 24) & 0xff;
  return out;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const part of parts) {
    total += part.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function bytesToBlock(bytes: Uint8Array, out: BigUint64Array): void {
  for (let k = 0; k < WORDS_PER_BLOCK; k++) {
    let word = 0n;
    for (let b = 0; b < 8; b++) {
      word |= BigInt(bytes[k * 8 + b] as number) << BigInt(8 * b);
    }
    out[k] = word;
  }
}

function blockToBytes(block: BigUint64Array): Uint8Array {
  const out = new Uint8Array(1024);
  for (let k = 0; k < WORDS_PER_BLOCK; k++) {
    const word = block[k] as bigint;
    for (let b = 0; b < 8; b++) {
      out[k * 8 + b] = Number((word >> BigInt(8 * b)) & 0xffn);
    }
  }
  return out;
}

/**
 * Variable-length hash function H' (RFC 9106, Section 3.3), built on BLAKE2b.
 */
function hPrime(outLength: number, input: Uint8Array): Uint8Array {
  if (outLength <= 64) {
    return blake2b(outLength, concatBytes(le32(outLength), input));
  }
  const out = new Uint8Array(outLength);
  const blocks = Math.ceil(outLength / 32) - 2;
  let v = blake2b(64, concatBytes(le32(outLength), input));
  out.set(v.subarray(0, 32), 0);
  let pos = 32;
  for (let i = 2; i <= blocks; i++) {
    v = blake2b(64, v);
    out.set(v.subarray(0, 32), pos);
    pos += 32;
  }
  out.set(blake2b(outLength - 32 * blocks, v), pos);
  return out;
}

// Index patterns for the BLAKE2b permutation P over a 1024-byte block, viewed
// as an 8x8 matrix of 16-byte registers (RFC 9106, Section 3.5). Rows are 16
// consecutive words; columns stride through the block.
const ROWS: number[][] = [];
const COLS: number[][] = [];
for (let r = 0; r < 8; r++) {
  const row: number[] = [];
  const col: number[] = [];
  for (let k = 0; k < 16; k++) {
    row.push(16 * r + k);
  }
  for (let k = 0; k < 8; k++) {
    col.push(2 * r + 16 * k);
    col.push(2 * r + 16 * k + 1);
  }
  ROWS.push(row);
  COLS.push(col);
}

/** GB, the modified BLAKE2b mixing function with multiplications (Section 3.6). */
function gb(v: BigUint64Array, a: number, b: number, c: number, d: number): void {
  let va = v[a] as bigint;
  let vb = v[b] as bigint;
  let vc = v[c] as bigint;
  let vd = v[d] as bigint;
  va = (va + vb + 2n * (va & M32) * (vb & M32)) & M64;
  vd = rotr64(vd ^ va, 32n);
  vc = (vc + vd + 2n * (vc & M32) * (vd & M32)) & M64;
  vb = rotr64(vb ^ vc, 24n);
  va = (va + vb + 2n * (va & M32) * (vb & M32)) & M64;
  vd = rotr64(vd ^ va, 16n);
  vc = (vc + vd + 2n * (vc & M32) * (vd & M32)) & M64;
  vb = rotr64(vb ^ vc, 63n);
  v[a] = va;
  v[b] = vb;
  v[c] = vc;
  v[d] = vd;
}

/** Permutation P applied to the 16 words named by `q` (RFC 9106, Section 3.6). */
function permute(v: BigUint64Array, q: number[]): void {
  const i = (k: number): number => q[k] as number;
  gb(v, i(0), i(4), i(8), i(12));
  gb(v, i(1), i(5), i(9), i(13));
  gb(v, i(2), i(6), i(10), i(14));
  gb(v, i(3), i(7), i(11), i(15));
  gb(v, i(0), i(5), i(10), i(15));
  gb(v, i(1), i(6), i(11), i(12));
  gb(v, i(2), i(7), i(8), i(13));
  gb(v, i(3), i(4), i(9), i(14));
}

/**
 * Compression function G (RFC 9106, Section 3.5):
 * `next = (with_xor ? next : 0) XOR R XOR P_columns(P_rows(R))`,
 * where `R = ref XOR prev`.
 */
function fillBlock(
  prev: BigUint64Array,
  ref: BigUint64Array,
  next: BigUint64Array,
  withXor: boolean,
): void {
  const r = new BigUint64Array(WORDS_PER_BLOCK);
  for (let k = 0; k < WORDS_PER_BLOCK; k++) {
    r[k] = (ref[k] as bigint) ^ (prev[k] as bigint);
  }
  const tmp = new BigUint64Array(WORDS_PER_BLOCK);
  if (withXor) {
    for (let k = 0; k < WORDS_PER_BLOCK; k++) {
      tmp[k] = (r[k] as bigint) ^ (next[k] as bigint);
    }
  } else {
    tmp.set(r);
  }
  for (let i = 0; i < 8; i++) {
    permute(r, ROWS[i] as number[]);
  }
  for (let i = 0; i < 8; i++) {
    permute(r, COLS[i] as number[]);
  }
  for (let k = 0; k < WORDS_PER_BLOCK; k++) {
    next[k] = (tmp[k] as bigint) ^ (r[k] as bigint);
  }
}

/**
 * Map a pseudo-random value to a reference block index within a lane
 * (RFC 9106, Section 3.4.2; reference implementation `index_alpha`).
 */
function indexAlpha(
  pass: number,
  slice: number,
  index: number,
  segmentLength: number,
  laneLength: number,
  pseudoRand: number,
  sameLane: boolean,
): number {
  let referenceAreaSize: number;
  if (pass === 0) {
    if (slice === 0) {
      referenceAreaSize = index - 1;
    } else if (sameLane) {
      referenceAreaSize = slice * segmentLength + index - 1;
    } else {
      referenceAreaSize = slice * segmentLength + (index === 0 ? -1 : 0);
    }
  } else if (sameLane) {
    referenceAreaSize = laneLength - segmentLength + index - 1;
  } else {
    referenceAreaSize = laneLength - segmentLength + (index === 0 ? -1 : 0);
  }

  let relative = BigInt(pseudoRand);
  relative = (relative * relative) >> 32n;
  relative = BigInt(referenceAreaSize) - 1n - ((BigInt(referenceAreaSize) * relative) >> 32n);

  let startPosition = 0;
  if (pass !== 0) {
    startPosition = slice === SYNC_POINTS - 1 ? 0 : (slice + 1) * segmentLength;
  }
  return Number((BigInt(startPosition) + relative) % BigInt(laneLength));
}

/** Run the full Argon2 operation and return the tag. */
export function argon2Core(params: CoreParams): Uint8Array {
  const { password, salt, secret, associatedData } = params;
  const lanes = params.parallelism;
  const memory = params.memory;
  const passes = params.iterations;
  const tagLength = params.tagLength;
  const version = params.version;
  const type = params.type;

  // Step 1: H_0.
  const h0 = blake2b(
    64,
    concatBytes(
      le32(lanes),
      le32(tagLength),
      le32(memory),
      le32(passes),
      le32(version),
      le32(type),
      le32(password.length),
      password,
      le32(salt.length),
      salt,
      le32(secret.length),
      secret,
      le32(associatedData.length),
      associatedData,
    ),
  );

  // Step 2: allocate memory matrix B[lanes][columns].
  const memoryBlocks = 4 * lanes * Math.floor(memory / (4 * lanes));
  const columns = memoryBlocks / lanes;
  const segmentLength = columns / SYNC_POINTS;
  const store = new BigUint64Array(memoryBlocks * WORDS_PER_BLOCK);

  const block = (lane: number, col: number): BigUint64Array => {
    const start = (lane * columns + col) * WORDS_PER_BLOCK;
    return store.subarray(start, start + WORDS_PER_BLOCK);
  };

  // Steps 3-4: first two columns of each lane.
  for (let lane = 0; lane < lanes; lane++) {
    bytesToBlock(hPrime(1024, concatBytes(h0, le32(0), le32(lane))), block(lane, 0));
    bytesToBlock(hPrime(1024, concatBytes(h0, le32(1), le32(lane))), block(lane, 1));
  }

  const zeroBlock = new BigUint64Array(WORDS_PER_BLOCK);

  const fillSegment = (pass: number, slice: number, lane: number): void => {
    const dataIndependent = type === ARGON2_ID && pass === 0 && slice < SYNC_POINTS / 2;

    let addressBlock = zeroBlock;
    let inputBlock = zeroBlock;
    const nextAddresses = (): void => {
      inputBlock[6] = (inputBlock[6] as bigint) + 1n;
      fillBlock(zeroBlock, inputBlock, addressBlock, false);
      fillBlock(zeroBlock, addressBlock, addressBlock, false);
    };

    if (dataIndependent) {
      addressBlock = new BigUint64Array(WORDS_PER_BLOCK);
      inputBlock = new BigUint64Array(WORDS_PER_BLOCK);
      inputBlock[0] = BigInt(pass);
      inputBlock[1] = BigInt(lane);
      inputBlock[2] = BigInt(slice);
      inputBlock[3] = BigInt(memoryBlocks);
      inputBlock[4] = BigInt(passes);
      inputBlock[5] = BigInt(type);
    }

    let startIndex = 0;
    if (pass === 0 && slice === 0) {
      startIndex = 2;
      if (dataIndependent) {
        nextAddresses();
      }
    }

    for (let index = startIndex; index < segmentLength; index++) {
      const col = slice * segmentLength + index;
      const prevCol = col === 0 ? columns - 1 : col - 1;

      let pseudoRand: bigint;
      if (dataIndependent) {
        if (index % ADDRESSES_PER_BLOCK === 0) {
          nextAddresses();
        }
        pseudoRand = addressBlock[index % ADDRESSES_PER_BLOCK] as bigint;
      } else {
        pseudoRand = block(lane, prevCol)[0] as bigint;
      }

      let refLane = Number((pseudoRand >> 32n) % BigInt(lanes));
      if (pass === 0 && slice === 0) {
        refLane = lane;
      }

      const refIndex = indexAlpha(
        pass,
        slice,
        index,
        segmentLength,
        columns,
        Number(pseudoRand & M32),
        refLane === lane,
      );

      const withXor = version !== ARGON2_VERSION_10 && pass > 0;
      fillBlock(block(lane, prevCol), block(refLane, refIndex), block(lane, col), withXor);
    }
  };

  // Steps 5-6: fill the matrix, slicewise across all lanes.
  for (let pass = 0; pass < passes; pass++) {
    for (let slice = 0; slice < SYNC_POINTS; slice++) {
      for (let lane = 0; lane < lanes; lane++) {
        fillSegment(pass, slice, lane);
      }
    }
  }

  // Step 7: final block C is the XOR of the last column across lanes.
  const c = new BigUint64Array(WORDS_PER_BLOCK);
  for (let lane = 0; lane < lanes; lane++) {
    const last = block(lane, columns - 1);
    for (let k = 0; k < WORDS_PER_BLOCK; k++) {
      c[k] = (c[k] as bigint) ^ (last[k] as bigint);
    }
  }

  // Step 8: tag = H'^T(C).
  return hPrime(tagLength, blockToBytes(c));
}
