type Err<E extends unknown> = { ok: false; error: E };
type Ok<D extends unknown> = { ok: true; data: D };

export type Result<
  D extends unknown = undefined,
  E extends unknown = undefined,
> = Ok<D> | Err<E>;

export const err = <E>(e: E): Err<E> => ({ ok: false as const, error: e });
export const ok = <D>(d: D): Ok<D> => ({ ok: true as const, data: d });
