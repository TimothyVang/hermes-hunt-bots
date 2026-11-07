export class QemuPaneOwner {
  private ownerId: number | null = null

  claim(ownerId: number): void {
    this.ownerId = ownerId
  }

  release(ownerId: number): boolean {
    if (this.ownerId !== ownerId) return false
    this.ownerId = null
    return true
  }

  owns(ownerId: number): boolean {
    return this.ownerId === ownerId
  }
  get current(): number | null {
    return this.ownerId
  }

  get active(): boolean {
    return this.ownerId !== null
  }
}
