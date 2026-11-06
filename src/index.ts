/**
 * Copyright 2026 AyanWorks Technology Solutions Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

export {
  FetchOpenBaoClient,
  OpenBaoNotFoundError,
  OpenBaoRequestError,
  OpenBaoSealedError,
  OpenBaoUnreachableError,
  type FetchOpenBaoClientOptions,
  type OpenBaoClient,
  type OpenBaoHealth,
  type OpenBaoImportKeyOptions,
  type OpenBaoKeyType,
  type OpenBaoListKeysOptions,
  type OpenBaoSignOptions,
  type OpenBaoTransitKey,
} from './OpenBaoClient.js'

export {
  OPENBAO_KEY_ID_PREFIX,
  OpenBaoKeyManagementService,
  openBaoKeyId,
  type KeyNameScopeResolver,
  type OpenBaoKeyManagementServiceOptions,
} from './OpenBaoKeyManagementService.js'

export { AppRoleAuth, StaticTokenAuth, type AppRoleAuthOptions, type AuthProvider } from './auth.js'
