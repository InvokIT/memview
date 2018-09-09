export interface IStorage<T> {
    save(value: any): void,
    load(): T | null,
    clear(): void
}

export class LocalStorage<T> implements IStorage<T> {
    public readonly key: string

    constructor(key: string) {
        this.key = key;
    }

    public save(value: any) {
        window.localStorage.setItem(this.key, JSON.stringify(value));
    }

    public load(): T | null {
        const item = window.localStorage.getItem(this.key)
        return item ? JSON.parse(item) : null;
    }

    public clear() {
        window.localStorage.removeItem(this.key);
    }
}

export default LocalStorage;
