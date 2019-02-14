<?php

namespace DH\DoctrineAuditBundle\User;

use DH\DoctrineAuditBundle\User\User;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Security\Core\Role\SwitchUserRole;
use Symfony\Component\Security\Core\User\UserInterface as BaseUserInterface;
use DH\DoctrineAuditBundle\User\UserProviderInterface;
use DH\DoctrineAuditBundle\User\UserInterface;

class TokenStorageUserProvider implements UserProviderInterface
{
    private $tokenStorage;
    private $authorizationChecker;

    public function __construct(
        TokenStorageInterface $tokenStorage,
        AuthorizationCheckerInterface $authorizationChecker
    ) {
        $this->tokenStorage = $tokenStorage;
        $this->authorizationChecker = $authorizationChecker;
    }

    public function getUser(): ?UserInterface
    {
        $user = null;
        $token = $this->tokenStorage->getToken();

        if (null !== $token) {
            $tokenUser = $token->getUser();
            if ($tokenUser instanceof BaseUserInterface) {
                $impersonation = '';
                if ($this->authorizationChecker->isGranted('ROLE_PREVIOUS_ADMIN')) {
                    $impersonatorUser = null;
                    foreach ($this->tokenStorage->getToken()->getRoles() as $role) {
                        if ($role instanceof SwitchUserRole) {
                            $impersonatorUser = $role->getSource()->getUser();

                            break;
                        }
                    }
                    if ($impersonatorUser) {
                        $impersonation = ' [impersonator '.$impersonatorUser->getUsername().':'.$impersonatorUser->getId().']';
                    }
                }
                $user = new User($tokenUser->getId(), $tokenUser->getUsername().$impersonation);
            }
        }

        return $user;
    }
}
