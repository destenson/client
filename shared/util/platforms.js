/* @flow */
import type {PlatformsExpanded} from '../constants/types/more'

const FriendlyNames = {
  'none': 'None',
  'keybase': 'Keybase',
  'twitter': 'Twitter',
  'github': 'GitHub',
  'reddit': 'Reddit',
  'coinbase': 'Coinbase',
  'hackernews': 'Hacker News',
  'genericWebSite': 'Website',
  'http': 'Website',
  'https': 'Website',
  'dns': 'DNS',
  'pgp': 'PGP',
  'rooter': 'Rooter',
  'btc': 'Bitcoin',
}

export function friendlyName (platform: PlatformsExpanded) {
  return FriendlyNames[platform]
}

const ProveMessages = {
  'none': '',
  'keybase': '',
  'twitter': 'Prove your Twitter',
  'github': 'Prove your GitHub',
  'reddit': 'Prove your Reddit',
  'coinbase': 'Prove your Coinbase',
  'hackernews': 'Prove your Hacker News',
  'genericWebSite': 'Prove your website',
  'http': 'Prove your website',
  'https': 'Prove your website',
  'dns': 'Prove your website',
  'pgp': 'Add a PGP key',
  'rooter': 'Prove your Rooter',
  'btc': 'Set a Bitcoin address',
}

export function proveMessage (platform: PlatformsExpanded) {
  return ProveMessages[platform]
}

export function subtitle (platform: PlatformsExpanded): ?string {
  switch (platform) {
    case 'btc':
      return null
    case 'dns':
    case 'http':
    case 'https':
      return platform
    case 'genericWebSite':
      return 'http(s)'
    default:
      return `@${platform}`
  }
}
