<?php
namespace Auth\Controller;

use Zend\Mvc\Controller\AbstractActionController;
use Zend\View\Model\ViewModel;

use Zend\Authentication\Result;
use Zend\Authentication\AuthenticationService;
use Zend\Authentication\Storage\Session as SessionStorage;

use Zend\Db\Adapter\Adapter as DbAdapter;

//use Zend\Authentication\Adapter\DbTable as AuthAdapter;
use Zend\Authentication\Adapter\DbTable\CredentialTreatmentAdapter as AuthAdapter;

use Auth\Model\Auth;
use Auth\Form\AuthForm;

/*
 *
 * Instead of Zend\Authentication\Adapter\DbTable use new
Zend\Authentication\Adapter\DbTable\CredentialTreatmentAdapter
or
Zend\Authentication\Adapter\DbTable\CallbackCheckAdapter
*/

class IndexController extends AbstractActionController
{
    public function indexAction()
    {
        return new ViewModel();
    }

    public function loginAction()
    {
        $user = $this->identity();

        // call a form in From/AuthForm.php
        $form = new AuthForm();
        $form->get('submit')->setValue('Login');
        $messages = null;

        $request = $this->getRequest(); // read request, was it post or get method

        if ($request->isPost()) {
            $authFormFilters = new Auth();
            $form->setInputFilter($authFormFilters->getInputFilter());
            $form->setData($request->getPost());

            if ($form->isValid()) {
                $data = $form->getData();
                $sm = $this->getServiceLocator();

                // Adapter need configuration on database.local.php and global.php
                $dbAdapter = $sm->get('Zend\Db\Adapter\Adapter');

                // Takes entire configuration from global.php
                $config = $this->getServiceLocator()->get('Config');

                // and this is how yoy get specific element of configuration
                $staticSalt = $config['static_salt'];

                $authAdapter = new AuthAdapter($dbAdapter,
                    'users', // there is a method setTableName to do the same
                    'usr_name', // there is a method setIdentityColumn to do the same
                    'usr_password', // there is a method setCredentialColumn to do the same
                    "MD5(CONCAT('$staticSalt', ?, usr_password_salt)) AND usr_active = 1" // setCredentialTreatment(parametrized string) 'MD5(?)'
                );
                $authAdapter
                    ->setIdentity($data['usr_name'])
                    ->setCredential($data['usr_password'])
                ;

                // AuthenticationService() is one container for 2 adapters
                // One is Authentication Adapter and the other is Storage
                $auth = new AuthenticationService();
                // or prepare in the globa.config.php and get it from there. Better to be in a module, so we can replace in another module.
                // $auth = $this->getServiceLocator()->get('Zend\Authentication\AuthenticationService');
                // $sm->setService('Zend\Authentication\AuthenticationService', $auth); // You can set the service here but will be loaded only if this action called.
                $result = $auth->authenticate($authAdapter);

                switch ($result->getCode()) {
                    case Result::FAILURE_IDENTITY_NOT_FOUND:
                        // do stuff for nonexistent identity
                        break;

                    case Result::FAILURE_CREDENTIAL_INVALID:
                        // do stuff for invalid credential
                        break;

                    case Result::SUCCESS:
                        // everything what we took from db will be written to session
                        $storage = $auth->getStorage();
                        $storage->write($authAdapter->getResultRowObject(
                            null,
                            'usr_password'
                        ));
                        // this is time for cookie
                        $time = 1209600; // 14 days 1209600/3600 = 336 hours => 336/24 = 14 days
//						if ($data['rememberme']) $storage->getSession()->getManager()->rememberMe($time); // no way to get the session

                        // if remember me checkbox has beem checked store cookie using session manager
                        if ($data['rememberme']) {
                            $sessionManager = new \Zend\Session\SessionManager();
                            $sessionManager->rememberMe($time); // set cookie for the duration of the time 14 days
                        }
                        break;

                    default:
                        // do stuff for other failure
                        break;
                }
                foreach ($result->getMessages() as $message) {
                    $messages .= "$message\n";
                }
            }
        }
        return new ViewModel(array('form' => $form, 'messages' => $messages));
    }

    public function logoutAction()
    {
        $auth = new AuthenticationService();
        // or prepare in the globa.config.php and get it from there
        // $auth = $this->getServiceLocator()->get('Zend\Authentication\AuthenticationService');

        if ($auth->hasIdentity()) {
            $identity = $auth->getIdentity();
        }

        // if user didn't clicked remember me
        $auth->clearIdentity(); // removes cookie and user if logged out
//		$auth->getStorage()->session->getManager()->forgetMe(); // no way to get the sessionmanager from storage

        // if user clicked rememeber me box then you need to destroy cookie too
        $sessionManager = new \Zend\Session\SessionManager();
        $sessionManager->forgetMe(); // to destroy cookie

        return $this->redirect()->toRoute('auth/default', array('controller' => 'index', 'action' => 'login'));
    }
}