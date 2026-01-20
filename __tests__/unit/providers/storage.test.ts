import { describe, it, expect, beforeEach } from 'vitest';
import { createBrowserStorage } from '../../../src/providers/storage.js';

describe('BrowserStorage', () => {
  describe('MemoryStorage', () => {
    it('should store and retrieve values', async () => {
      const storage = createBrowserStorage({ storage: 'memory' });

      await storage.set('key1', 'value1');
      const value = await storage.get('key1');

      expect(value).toBe('value1');
    });

    it('should return null for non-existent keys', async () => {
      const storage = createBrowserStorage({ storage: 'memory' });

      const value = await storage.get('non-existent');

      expect(value).toBeNull();
    });

    it('should remove values', async () => {
      const storage = createBrowserStorage({ storage: 'memory' });

      await storage.set('key1', 'value1');
      await storage.remove('key1');
      const value = await storage.get('key1');

      expect(value).toBeNull();
    });

    it('should get all values', async () => {
      const storage = createBrowserStorage({ storage: 'memory' });

      await storage.set('key1', 'value1');
      await storage.set('key2', 'value2');
      const all = await storage.getAll?.();

      expect(all).toEqual({
        key1: 'value1',
        key2: 'value2',
      });
    });

    it('should clear all values', async () => {
      const storage = createBrowserStorage({ storage: 'memory' });

      await storage.set('key1', 'value1');
      await storage.set('key2', 'value2');
      await storage.clear?.();

      expect(await storage.get('key1')).toBeNull();
      expect(await storage.get('key2')).toBeNull();
    });
  });

  describe('WebStorage (sessionStorage)', () => {
    beforeEach(() => {
      sessionStorage.clear();
    });

    it('should use sessionStorage by default', async () => {
      const storage = createBrowserStorage();

      await storage.set('test', 'value');

      expect(sessionStorage.getItem('authrim:test')).toBe('value');
    });

    it('should use custom prefix', async () => {
      const storage = createBrowserStorage({ prefix: 'custom' });

      await storage.set('test', 'value');

      expect(sessionStorage.getItem('custom:test')).toBe('value');
    });

    it('should retrieve values', async () => {
      const storage = createBrowserStorage();

      sessionStorage.setItem('authrim:test', 'stored-value');
      const value = await storage.get('test');

      expect(value).toBe('stored-value');
    });

    it('should remove values', async () => {
      const storage = createBrowserStorage();

      sessionStorage.setItem('authrim:test', 'value');
      await storage.remove('test');

      expect(sessionStorage.getItem('authrim:test')).toBeNull();
    });

    it('should get all prefixed values', async () => {
      const storage = createBrowserStorage();

      sessionStorage.setItem('authrim:key1', 'value1');
      sessionStorage.setItem('authrim:key2', 'value2');
      sessionStorage.setItem('other:key3', 'value3'); // Should not be included

      const all = await storage.getAll?.();

      expect(all).toEqual({
        key1: 'value1',
        key2: 'value2',
      });
    });

    it('should clear only prefixed values', async () => {
      const storage = createBrowserStorage();

      sessionStorage.setItem('authrim:key1', 'value1');
      sessionStorage.setItem('other:key2', 'value2');
      await storage.clear?.();

      expect(sessionStorage.getItem('authrim:key1')).toBeNull();
      expect(sessionStorage.getItem('other:key2')).toBe('value2');
    });
  });

  describe('WebStorage (localStorage)', () => {
    beforeEach(() => {
      localStorage.clear();
    });

    it('should use localStorage when specified', async () => {
      const storage = createBrowserStorage({ storage: 'localStorage' });

      await storage.set('test', 'value');

      expect(localStorage.getItem('authrim:test')).toBe('value');
    });
  });
});
