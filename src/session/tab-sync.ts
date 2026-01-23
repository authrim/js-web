/**
 * Tab Sync Manager
 *
 * Manages session synchronization between browser tabs using BroadcastChannel.
 * Includes leader election for coordinating token refresh.
 */

import type { EventEmitter, Session } from "@authrim/core";

/**
 * Tab sync message types
 */
export type TabSyncMessageType =
  | "heartbeat"
  | "session_change"
  | "logout"
  | "leader_claim"
  | "leader_release";

/**
 * Tab sync message
 */
export interface TabSyncMessage {
  type: TabSyncMessageType;
  tabId: string;
  timestamp: number;
  data?: unknown;
}

/**
 * Tab sync configuration
 */
export interface TabSyncConfig {
  /** Channel name (default: 'authrim-session') */
  channelName?: string;
  /** Heartbeat interval in milliseconds (default: 5000) */
  heartbeatIntervalMs?: number;
  /** Leader timeout in milliseconds (default: 15000) */
  leaderTimeoutMs?: number;
  /** Event emitter for session events */
  eventEmitter?: EventEmitter;
}

/**
 * Tab Sync Manager
 *
 * Synchronizes authentication state across browser tabs.
 * Uses leader election to coordinate token refresh.
 */
export class TabSyncManager {
  private channel: BroadcastChannel | null = null;
  private tabId: string;
  private isLeader = false;
  private leaderTabId: string | null = null;
  private lastLeaderHeartbeat = 0;
  private heartbeatInterval: ReturnType<typeof setInterval> | null = null;
  private leaderCheckInterval: ReturnType<typeof setInterval> | null = null;

  private readonly config: Required<Omit<TabSyncConfig, "eventEmitter">> & {
    eventEmitter?: EventEmitter;
  };
  private readonly onLeaderChangeCallbacks = new Set<
    (isLeader: boolean) => void
  >();

  /** Default heartbeat interval: 5 seconds */
  private static readonly DEFAULT_HEARTBEAT_INTERVAL_MS = 5000;

  /** Default leader timeout: 15 seconds */
  private static readonly DEFAULT_LEADER_TIMEOUT_MS = 15000;

  constructor(config?: TabSyncConfig) {
    // Generate unique tab ID
    this.tabId = this.generateTabId();

    this.config = {
      channelName: config?.channelName ?? "authrim-session",
      heartbeatIntervalMs:
        config?.heartbeatIntervalMs ??
        TabSyncManager.DEFAULT_HEARTBEAT_INTERVAL_MS,
      leaderTimeoutMs:
        config?.leaderTimeoutMs ?? TabSyncManager.DEFAULT_LEADER_TIMEOUT_MS,
      eventEmitter: config?.eventEmitter,
    };
  }

  /**
   * Generate unique tab ID
   */
  private generateTabId(): string {
    const array = new Uint8Array(8);
    if (typeof crypto !== "undefined" && crypto.getRandomValues) {
      crypto.getRandomValues(array);
    } else {
      // Fallback for older browsers
      for (let i = 0; i < array.length; i++) {
        array[i] = Math.floor(Math.random() * 256);
      }
    }
    return Array.from(array, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  /**
   * Initialize tab sync
   */
  initialize(): void {
    // Check if BroadcastChannel is supported
    if (typeof BroadcastChannel === "undefined") {
      return;
    }

    try {
      this.channel = new BroadcastChannel(this.config.channelName);
      this.channel.onmessage = this.handleMessage.bind(this);

      // Start heartbeat
      this.startHeartbeat();

      // Start leader check
      this.startLeaderCheck();

      // Claim leadership initially (first tab to claim wins)
      this.claimLeadership();
    } catch {
      // BroadcastChannel not supported or blocked
      this.channel = null;
    }
  }

  /**
   * Handle incoming messages
   */
  private handleMessage(event: MessageEvent): void {
    const message = event.data as TabSyncMessage;
    if (!message || message.tabId === this.tabId) {
      return; // Ignore own messages
    }

    switch (message.type) {
      case "heartbeat":
        this.handleHeartbeat(message);
        break;
      case "session_change":
        this.handleSessionChange(message);
        break;
      case "logout":
        this.handleLogout(message);
        break;
      case "leader_claim":
        this.handleLeaderClaim(message);
        break;
      case "leader_release":
        this.handleLeaderRelease(message);
        break;
    }
  }

  /**
   * Handle heartbeat from other tabs
   */
  private handleHeartbeat(message: TabSyncMessage): void {
    if (message.tabId === this.leaderTabId) {
      this.lastLeaderHeartbeat = Date.now();
    }
  }

  /**
   * Handle session change from other tabs
   */
  private handleSessionChange(message: TabSyncMessage): void {
    this.config.eventEmitter?.emit("session:sync", {
      action: "refresh",
      sourceTabId: message.tabId,
      timestamp: Date.now(),
      source: "web",
    });
  }

  /**
   * Handle logout from other tabs
   */
  private handleLogout(message: TabSyncMessage): void {
    this.config.eventEmitter?.emit("session:logout:broadcast", {
      sourceTabId: message.tabId,
      timestamp: Date.now(),
      source: "web",
    });
  }

  /**
   * Handle leader claim from other tabs
   */
  private handleLeaderClaim(message: TabSyncMessage): void {
    // If another tab claims leadership and we thought we were leader,
    // compare tab IDs to determine actual leader (higher ID wins for consistency)
    if (this.isLeader) {
      if (message.tabId > this.tabId) {
        // Other tab wins
        this.isLeader = false;
        this.leaderTabId = message.tabId;
        this.lastLeaderHeartbeat = Date.now();
        this.notifyLeaderChange();
      }
      // Otherwise, we stay leader
    } else {
      // Accept the new leader
      this.leaderTabId = message.tabId;
      this.lastLeaderHeartbeat = Date.now();
    }
  }

  /**
   * Handle leader release from other tabs
   */
  private handleLeaderRelease(message: TabSyncMessage): void {
    if (message.tabId === this.leaderTabId) {
      this.leaderTabId = null;
      // Try to claim leadership
      this.claimLeadership();
    }
  }

  /**
   * Start heartbeat
   */
  private startHeartbeat(): void {
    this.heartbeatInterval = setInterval(() => {
      if (this.isLeader) {
        this.send({
          type: "heartbeat",
          tabId: this.tabId,
          timestamp: Date.now(),
        });
      }
    }, this.config.heartbeatIntervalMs);
  }

  /**
   * Start leader check
   */
  private startLeaderCheck(): void {
    this.leaderCheckInterval = setInterval(() => {
      if (!this.isLeader && this.leaderTabId) {
        const timeSinceLastHeartbeat = Date.now() - this.lastLeaderHeartbeat;
        if (timeSinceLastHeartbeat > this.config.leaderTimeoutMs) {
          // Leader timed out, claim leadership
          this.claimLeadership();
        }
      }
    }, this.config.heartbeatIntervalMs);
  }

  /**
   * Claim leadership
   */
  private claimLeadership(): void {
    this.isLeader = true;
    this.leaderTabId = this.tabId;
    this.lastLeaderHeartbeat = Date.now();
    this.send({
      type: "leader_claim",
      tabId: this.tabId,
      timestamp: Date.now(),
    });
    this.notifyLeaderChange();
  }

  /**
   * Release leadership
   */
  private releaseLeadership(): void {
    if (this.isLeader) {
      this.isLeader = false;
      this.send({
        type: "leader_release",
        tabId: this.tabId,
        timestamp: Date.now(),
      });
    }
  }

  /**
   * Send a message to other tabs
   */
  private send(message: TabSyncMessage): void {
    try {
      this.channel?.postMessage(message);
    } catch {
      // Channel might be closed
    }
  }

  /**
   * Notify leader change callbacks
   */
  private notifyLeaderChange(): void {
    for (const callback of this.onLeaderChangeCallbacks) {
      try {
        callback(this.isLeader);
      } catch {
        // Ignore callback errors
      }
    }

    // Emit session:sync event for leader change
    this.config.eventEmitter?.emit("session:sync", {
      action: "leader_change",
      sourceTabId: this.tabId,
      timestamp: Date.now(),
      source: "web",
    });
  }

  /**
   * Check if this tab is the leader
   */
  get leader(): boolean {
    return this.isLeader;
  }

  /**
   * Get this tab's ID
   */
  get id(): string {
    return this.tabId;
  }

  /**
   * Register callback for leader changes
   *
   * @param callback - Called when leadership changes
   * @returns Unsubscribe function
   */
  onLeaderChange(callback: (isLeader: boolean) => void): () => void {
    this.onLeaderChangeCallbacks.add(callback);
    return () => {
      this.onLeaderChangeCallbacks.delete(callback);
    };
  }

  /**
   * Broadcast session change to other tabs
   */
  broadcastSessionChange(session: Session | null): void {
    this.send({
      type: "session_change",
      tabId: this.tabId,
      timestamp: Date.now(),
      data: { hasSession: !!session },
    });
  }

  /**
   * Broadcast logout to other tabs
   */
  broadcastLogout(): void {
    this.send({
      type: "logout",
      tabId: this.tabId,
      timestamp: Date.now(),
    });
  }

  /**
   * Destroy and clean up
   */
  destroy(): void {
    // Release leadership before closing
    this.releaseLeadership();

    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }

    if (this.leaderCheckInterval) {
      clearInterval(this.leaderCheckInterval);
      this.leaderCheckInterval = null;
    }

    this.channel?.close();
    this.channel = null;
    this.onLeaderChangeCallbacks.clear();
  }
}
