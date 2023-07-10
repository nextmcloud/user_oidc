# MagentaCLOUD user_oidc

Customisation of the Nextcloud delivered OpenID connect app for MagentaCLOUD.

The app extends the standard `user_oidc` Nextcloud app,
see [upstream configuration hints for basic setup](https://github.com/nextcloud/user_oidc/blob/main/README.md)

The app is extended by the following features:

## Event-based provisioning (upstream contribution candidate)
The mechanism allows to implement custom puser provisioning logic in a separate Nextcloud app by
registering and handling a attribute change and provisioning event:

```
use OCP\AppFramework\App;
use OCP\AppFramework\Bootstrap\IBootContext;
use OCP\AppFramework\Bootstrap\IBootstrap;
use OCP\AppFramework\Bootstrap\IRegistrationContext;

class Application extends App implements IBootstrap {
...
	public function register(IRegistrationContext $context): void {
		$context->registerEventListener(AttributeMappedEvent::class, MyUserAttributeListener::class);
		$context->registerEventListener(UserAccountChangeEvent::class, MyUserAccountChangeListener::class);
	}
...
}
```
The provisioning handler should return a `OCA\UserOIDC\Event\UserAccountChangeResult` object

## Telekom-specific bearer token

Due to historic reason, Telekom bearer tokens have a close to standard structure, but
require special security implementation in detail. The customisation overrides te standard


### Requiring web-token libraries
The central configuration branch `nmc/2372-central-setup` automatic merge will frequently fail if composer
upstream 

The fast and easy way to bring it back to sync with upstream is:
```
git checkout nmc/2372-central-setup
git rebase --onto main nmc/2372-central-setup
# manually take over everything from upstream for composer.lock (TODO: automate that)

# update web-token dependencies in composer.lock
composer update web-token
```
It is recommended to leave the version management for all other libraries to upstream
and only update web-token with the dedicated `composer update web-token`. 


### Configuring an additional Bearer preshared secret with provider
TODO

### Testing Bearer secrets
TODO