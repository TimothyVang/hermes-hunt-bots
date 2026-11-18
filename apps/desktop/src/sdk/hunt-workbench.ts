import type {
  HuntBoardDiscoveryResult,
  HuntBoardStartRequest,
  HuntBoardStartResult,
  HuntGateDecisionRequest,
  HuntGateDecisionResult,
  HuntGateStatusResult,
  HuntWorkbenchApi
} from '../../electron/hunt-workbench'

const unavailable = <T extends { error?: string; ok: boolean }>(extra?: Partial<T>): T =>
  ({
    error: 'Hunt Command local workbench bridge is unavailable in this environment.',
    ok: false,
    ...extra
  }) as T

/** Hunt Command local loopback workbench bridge (`host.huntWorkbench`).
 *  Strictly click-driven: never issues IPC on module load or component mount. */
export const huntWorkbench: HuntWorkbenchApi = {
  decideGate: async (request: HuntGateDecisionRequest): Promise<HuntGateDecisionResult> => {
    const bridge = window.hermesDesktop?.huntWorkbench

    if (!bridge?.decideGate) {
      return unavailable<HuntGateDecisionResult>()
    }

    return bridge.decideGate(request)
  },

  discoverBoards: async (options?: { port?: number }): Promise<HuntBoardDiscoveryResult> => {
    const bridge = window.hermesDesktop?.huntWorkbench

    if (!bridge?.discoverBoards) {
      return unavailable<HuntBoardDiscoveryResult>({ boards: [] })
    }

    return bridge.discoverBoards(options)
  },

  gateStatus: async (request: { address?: string; workflowId: string }): Promise<HuntGateStatusResult> => {
    const bridge = window.hermesDesktop?.huntWorkbench

    if (!bridge?.gateStatus) {
      return unavailable<HuntGateStatusResult>()
    }

    return bridge.gateStatus(request)
  },

  startBoard: async (request: HuntBoardStartRequest): Promise<HuntBoardStartResult> => {
    const bridge = window.hermesDesktop?.huntWorkbench

    if (!bridge?.startBoard) {
      return unavailable<HuntBoardStartResult>()
    }

    return bridge.startBoard(request)
  },

  stopBoard: async (): Promise<{ ok: boolean; stopped: boolean }> => {
    const bridge = window.hermesDesktop?.huntWorkbench

    if (!bridge?.stopBoard) {
      return { ok: false, stopped: false }
    }

    return bridge.stopBoard()
  }
}

export type {
  HuntBoardDescriptor,
  HuntBoardDiscoveryResult,
  HuntBoardStartRequest,
  HuntBoardStartResult,
  HuntDataOrigin,
  HuntGateDecisionRecord,
  HuntGateDecisionRequest,
  HuntGateDecisionResult,
  HuntGateStatus,
  HuntGateStatusResult,
  HuntGateStepSummary,
  HuntOpenGate,
  HuntWorkbenchApi
} from '../../electron/hunt-workbench'
