import {
  GenericRecord,
  InjectionSymbols,
  RecordNotFoundError,
  type AgentContext,
  type StorageService,
} from '@credo-ts/core'
import type { KmsJwkPrivate } from '@credo-ts/core/kms'
import type { NodeKeyManagementStorage } from '@credo-ts/node'

/**
 * Persist Node.js KMS keys in the agent's own storage instead of memory.
 *
 * With Drizzle this means keys live in the same SQLite database as DIDs,
 * credentials, and other agent records, and survive restarts.
 */
export class DrizzleNodeKeyManagementStorage implements NodeKeyManagementStorage {
  #storage(agentContext: AgentContext): StorageService<GenericRecord> {
    return agentContext.resolve(InjectionSymbols.StorageService)
  }

  #recordId(keyId: string): string {
    return `node-kms-${keyId}`
  }

  public async get(agentContext: AgentContext, keyId: string): Promise<KmsJwkPrivate | null> {
    try {
      const record = await this.#storage(agentContext).getById(agentContext, GenericRecord, this.#recordId(keyId))
      return (record.content as { privateJwk?: KmsJwkPrivate }).privateJwk ?? null
    } catch (error) {
      if (error instanceof RecordNotFoundError) return null
      throw error
    }
  }

  public async has(agentContext: AgentContext, keyId: string): Promise<boolean> {
    return (await this.get(agentContext, keyId)) !== null
  }

  public async set(agentContext: AgentContext, keyId: string, jwk: KmsJwkPrivate): Promise<void> {
    const storage = this.#storage(agentContext)
    const id = this.#recordId(keyId)

    let record: GenericRecord | undefined
    try {
      record = await storage.getById(agentContext, GenericRecord, id)
    } catch (error) {
      if (!(error instanceof RecordNotFoundError)) throw error
    }

    if (record) {
      record.content = { privateJwk: jwk }
      await storage.update(agentContext, record)
    } else {
      await storage.save(agentContext, new GenericRecord({ id, content: { privateJwk: jwk } }))
    }
  }

  public async delete(agentContext: AgentContext, keyId: string): Promise<boolean> {
    try {
      await this.#storage(agentContext).deleteById(agentContext, GenericRecord, this.#recordId(keyId))
      return true
    } catch (error) {
      if (error instanceof RecordNotFoundError) return false
      throw error
    }
  }
}
