<?php

declare(strict_types=1);

namespace Shaarli\Front\Controller\Visitor;

use Shaarli\ApplicationUtils;
use Shaarli\Container\ShaarliContainer;
use Shaarli\Front\Exception\AlreadyInstalledException;
use Shaarli\Front\Exception\ResourcePermissionException;
use Shaarli\Languages;
use Slim\Http\Request;
use Slim\Http\Response;

class InstallController extends ShaarliVisitorController
{
    public function __construct(ShaarliContainer $container)
    {
        parent::__construct($container);

        if (is_file($this->container->conf->getConfigFileExt())) {
            throw new AlreadyInstalledException();
        }
    }

    public function index(Request $request, Response $response): Response
    {
        $this->checkPermissions();

        // This part makes sure sessions works correctly.
        // (Because on some hosts, session.save_path may not be set correctly,
        // or we may not have write access to it.)
        if (null !== $request->getParam('test_session')
            && 'Working' !== $this->container->sessionManager->getSessionParameter('session_tested')
        ) {
            // Step 2: Check if data in session is correct.
            $msg = t(
                '<pre>Sessions do not seem to work correctly on your server.<br>'.
                'Make sure the variable "session.save_path" is set correctly in your PHP config, '.
                'and that you have write access to it.<br>'.
                'It currently points to %s.<br>'.
                'On some browsers, accessing your server via a hostname like \'localhost\' '.
                'or any custom hostname without a dot causes cookie storage to fail. '.
                'We recommend accessing your server via it\'s IP address or Fully Qualified Domain Name.<br>'
            );
            $msg = sprintf($msg, $this->container->sessionManager->getSavePath());

            $this->assignView('message', $msg);

            return $response->write($this->render('error'));
        }

        if ('Working' !== $this->container->sessionManager->getSessionParameter('session_tested')) {
            // Step 1 : Try to store data in session and reload page.
            $this->container->sessionManager->setSessionParameter('session_tested', 'Working');

            return $this->redirect($response, '/install?test_session');
        }

        if (null !== $request->getParam('test_session')) {
            // Step 3: Sessions are OK. Remove test parameter from URL.
            return $this->redirect($response, '/install');
        }

        [$continents, $cities] = generateTimeZoneData(timezone_identifiers_list(), date_default_timezone_get());

        $this->assignView('continents', $continents);
        $this->assignView('cities', $cities);
        $this->assignView('languages', Languages::getAvailableLanguages());

        return $response->write($this->render('install'));
    }

    public function install(Request $request, Response $response): Response
    {
        $timezone = 'UTC';
        if (!empty($request->getParam('continent'))
            && !empty($request->getParam('city'))
            && isTimeZoneValid($request->getParam('continent'), $request->getParam('city'))
        ) {
            $timezone = $request->getParam('continent') . '/' . $request->getParam('city');
        }
        $this->container->conf->set('general.timezone', $timezone);
        $login = $request->getParam('setlogin');
        $this->container->conf->set('credentials.login', $login);
        $salt = sha1(uniqid('', true) .'_'. mt_rand());
        $this->container->conf->set('credentials.salt', $salt);
        $this->container->conf->set('credentials.hash', sha1($request->getParam('setpassword') . $login . $salt));
        if (!empty($request->getParam('title'))) {
            $this->container->conf->set('general.title', escape($request->getParam('title')));
        } else {
            $this->container->conf->set('general.title', 'Shared bookmarks on '.escape(index_url($_SERVER)));
        }
        $this->container->conf->set('translation.language', escape($request->getParam('language')));
        $this->container->conf->set('updates.check_updates', !empty($request->getParam('updateCheck')));
        $this->container->conf->set('api.enabled', !empty($request->getParam('enableApi')));
        $this->container->conf->set(
            'api.secret',
            generate_api_secret(
                $this->container->conf->get('credentials.login'),
                $this->container->conf->get('credentials.salt')
            )
        );
        try {
            // Everything is ok, let's create config file.
            $this->container->conf->write($this->container->loginManager->isLoggedIn());
        } catch (\Exception $e) {
            error_log(
                'ERROR while writing config file after installation.' . PHP_EOL .
                $e->getMessage()
            );

            $this->assignView('message', $e->getMessage());

            return $response->write($this->render('error'));
        }

        if ($this->container->bookmarkService->count() === 0) {
            $this->container->bookmarkService->initialize();
        }

        return $this->redirect($response, '/');

        echo '<script>alert('
            .'"Shaarli is now configured. '
            .'Please enter your login/password and start shaaring your bookmarks!"'
            .');document.location=\'./login\';</script>';
        exit;
    }

    protected function checkPermissions(): bool
    {
        // Ensure Shaarli has proper access to its resources
        $errors = ApplicationUtils::checkResourcePermissions($this->container->conf);

        if (empty($errors)) {
            return true;
        }

        // FIXME! Do not insert HTML here.
        $message = '<p>'. t('Insufficient permissions:') .'</p><ul>';

        foreach ($errors as $error) {
            $message .= '<li>'.$error.'</li>';
        }
        $message .= '</ul>';

        throw new ResourcePermissionException($message);
    }
}
