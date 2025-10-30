# MagentaCLOUD user_oidc

Customisation of the Nextcloud delivered OpenID connect app for MagentaCLOUD.

The app extends the standard `user_oidc` Nextcloud app,
see [upstream configuration hints for basic setup](https://github.com/nextcloud/user_oidc/blob/main/README.md)


## Feature: Event-based provisioning (upstream contribution candidate)
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

## Feature: Telekom-specific bearer token

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
# ALWAYS update web-token dependencies in composer.lock
# to avoid upstream conflicts. The lock file diff should only contain adds to upstream state!
composer update "web-token/jwt-*"
```


### Configuring an additional Bearer preshared secret with provider
TODO

### Testing Bearer secrets
TODO
