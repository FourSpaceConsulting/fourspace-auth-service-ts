/**
 * Simple in-memory map DAO
 */
export class MemoryDao<T extends object, ID, SC> {
  private readonly data: Map<ID, T> = new Map();
  private count: number = 1;
  private _key: string;
  private _predicate: (t: T, sc: SC) => boolean;
  private _timeout: number;

  constructor(
    key: string,
    predicate: (t: T, sc: SC) => boolean,
    timeout: number = 0,
    items?: ReadonlyArray<T>
  ) {
    this._key = key;
    this._predicate = predicate;
    this._timeout = timeout;
    if (items != null) {
      items.map(i => this._save(i));
    }
  }

  private _getId(t: T): ID {
    return (t as any)[this._key];
  }

  private _save(item: T): T {
    const obj: any = Object.assign({}, item);
    if (this._getId(obj) == null) {
      obj[this._key] = this.newId();
    }
    this.data.set(this._getId(obj), obj);
    return obj;
  }

  getById(id: ID): Promise<T> {
    return new Promise(resolve => {
      setTimeout(() => resolve(this.data.get(id)), this._timeout);
    });
  }

  get(): Promise<T[]> {
    return new Promise(resolve => {
      setTimeout(() => resolve(Array.from(this.data.values())), this._timeout);
    });
  }

  search(sc: SC): Promise<T[]> {
    return new Promise(resolve => {
      setTimeout(
        () =>
          resolve(
            Array.from(this.data.values()).filter(i => this._predicate(i, sc))
          ),
        this._timeout
      );
    });
  }

  save(item: T): Promise<T> {
    return new Promise(resolve => {
      const obj = this._save(item);
      setTimeout(() => resolve(obj), this._timeout);
    });
  }

  saveAll(item: ReadonlyArray<T>): Promise<T[]> {
    return Promise.resolve(item.map(i => this._save(i)));
  }

  delete(id: ID): Promise<void> {
    return new Promise(resolve => {
      this.data.delete(id);
      setTimeout(() => resolve(), this._timeout);
    });
  }

  deleteItem(item: T): Promise<void> {
    const id: ID = this._getId(item);
    return this.delete(id);
  }

  newId(): number {
    const ids: any = Array.from(this.data.entries()).map(i =>
      this._getId(i[1])
    );
    const max = ids.length === 0 ? 0 : Math.max(...ids);
    return (isNaN(max) ? 0 : max) + 1;
  }
}
