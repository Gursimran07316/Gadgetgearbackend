<?php

namespace Drupal\custom_api\Controller;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Cookie;
use Drupal\Core\Controller\ControllerBase;
use Drupal\user\Entity\User;
use Drupal\key\Entity\Key;
use Firebase\JWT\JWT;
use Firebase\JWT\Key as JWTKey;

class UserAuthController extends ControllerBase {

  public function loginUser(Request $request) {
    $data = json_decode($request->getContent(), TRUE);
    $email = $data['email'] ?? '';
    $password = $data['password'] ?? '';

    if (empty($email) || empty($password)) {
      return new JsonResponse(['message' => 'Email and password are required.'], 400);
    }

    $users = \Drupal::entityTypeManager()
      ->getStorage('user')
      ->loadByProperties(['mail' => $email]);

    $user = reset($users);

    if (!$user || !$user->isActive()) {
      return new JsonResponse(['message' => 'Invalid user.'], 401);
    }

    $is_valid = \Drupal::service('user.auth')
      ->authenticate($user->getAccountName(), $password);

    if (!$is_valid) {
      return new JsonResponse(['message' => 'Invalid credentials.'], 403);
    }

    $secret = $this->getJwtSecret();
    $payload = [
      'uid' => $user->id(),
      'name' => $user->getAccountName(),
      'email' => $user->getEmail(),
      'exp' => time() + 30 * 24 * 60 * 60, // 30 days
    ];
    $jwt = JWT::encode($payload, $secret, 'HS256');

    $response = new JsonResponse([
      '_id' => $user->id(),
      'name' => $user->getAccountName(),
      'email' => $user->getEmail(),
      'isAdmin' => in_array('administrator', $user->getRoles()),
    ]);

    $response->headers->setCookie(new Cookie(
      'STYXKEY-jwt', $jwt, time() + 30 * 24 * 60 * 60, '/', null, true, true, false, 'None'
    ));

    return $response;
  }

  public function logoutUser(Request $request) {
    $response = new JsonResponse(['message' => 'Logged out successfully.'], 200);
    $response->headers->clearCookie('STYXKEY-jwt', '/', null, false, true, false, 'None');
    return $response;
  }

  public function registerUser(Request $request) {
    $data = json_decode($request->getContent(), TRUE);
    $name = $data['name'] ?? '';
    $email = $data['email'] ?? '';
    $password = $data['password'] ?? '';

    if (empty($name) || empty($email) || empty($password)) {
      return new JsonResponse(['message' => 'Name, email, and password are required.'], 400);
    }

    $existing = \Drupal::entityTypeManager()
      ->getStorage('user')
      ->loadByProperties(['mail' => $email]);

    if (!empty($existing)) {
      return new JsonResponse(['message' => 'User already exists.'], 400);
    }

    $user = User::create([
      'name' => $name,
      'mail' => $email,
      'pass' => $password,
      'status' => 1,
    ]);
    $user->enforceIsNew();
    $user->save();

    $secret = $this->getJwtSecret();
    $payload = [
      'uid' => $user->id(),
      'name' => $user->getAccountName(),
      'email' => $user->getEmail(),
      'exp' => time() + 30 * 24 * 60 * 60,
    ];
    $jwt = JWT::encode($payload, $secret, 'HS256');

    $response = new JsonResponse([
      '_id' => $user->id(),
      'name' => $user->getAccountName(),
      'email' => $user->getEmail(),
      'isAdmin' => in_array('administrator', $user->getRoles()),
    ], 201);

    $response->headers->setCookie(new Cookie(
      'STYXKEY-jwt', $jwt, time() + 30 * 24 * 60 * 60, '/', null, true, true, false, 'Lax'
    ));

    return $response;
  }

  public function getUsers() {
    try {
      $this->getAuthenticatedUser(true);

      $users = \Drupal::entityTypeManager()->getStorage('user')->loadMultiple();
      $data = [];

      foreach ($users as $user) {
        $data[] = [
          '_id' => $user->id(),
          'name' => $user->getAccountName(),
          'email' => $user->getEmail(),
          'isAdmin' => in_array('administrator', $user->getRoles()),
        ];
      }

      return new JsonResponse($data);
    } catch (\Exception $e) {
      return new JsonResponse(['message' => $e->getMessage()], $e->getCode() ?: 403);
    }
  }

  public function getUserById($id) {
    try {
      $this->getAuthenticatedUser(true);
      $user = User::load($id);

      if (!$user) {
        return new JsonResponse(['message' => 'User not found'], 404);
      }

      return new JsonResponse([
        '_id' => $user->id(),
        'name' => $user->getAccountName(),
        'email' => $user->getEmail(),
        'isAdmin' => in_array('administrator', $user->getRoles()),
      ]);
    } catch (\Exception $e) {
      return new JsonResponse(['message' => $e->getMessage()], $e->getCode() ?: 403);
    }
  }

  public function deleteUser($id) {
    try {
      $this->getAuthenticatedUser(true);
      $user = User::load($id);

      if (!$user) {
        return new JsonResponse(['message' => 'User not found'], 404);
      }

      if (in_array('administrator', $user->getRoles())) {
        return new JsonResponse(['message' => 'Cannot delete admin user'], 400);
      }

      $user->delete();
      return new JsonResponse(['message' => 'User removed']);
    } catch (\Exception $e) {
      return new JsonResponse(['message' => $e->getMessage()], $e->getCode() ?: 403);
    }
  }

  public function updateUser(Request $request, $id) {
    try {
      $this->getAuthenticatedUser(true);
      $data = json_decode($request->getContent(), TRUE);
      $user = User::load($id);

      if (!$user) {
        return new JsonResponse(['message' => 'User not found'], 404);
      }

      if (!empty($data['name'])) {
        $user->set('name', $data['name']);
      }
      if (!empty($data['email'])) {
        $user->set('mail', $data['email']);
      }

      if (isset($data['isAdmin'])) {
        $roles = $user->getRoles();
        if ((bool)$data['isAdmin']) {
          $roles[] = 'administrator';
        } else {
          $roles = array_diff($roles, ['administrator']);
        }
        $user->set('roles', array_unique($roles));
      }

      $user->save();

      return new JsonResponse([
        '_id' => $user->id(),
        'name' => $user->getAccountName(),
        'email' => $user->getEmail(),
        'isAdmin' => in_array('administrator', $user->getRoles()),
      ]);
    } catch (\Exception $e) {
      return new JsonResponse(['message' => $e->getMessage()], $e->getCode() ?: 403);
    }
  }

  // ---------------------
  // 🔐 Shared Helper Methods
  // ---------------------

  private function getJwtSecret() {
    $key = Key::load('simple_oauth');
    $secret = $key ? $key->getKeyValue() : '';
    if (!$secret) {
      throw new \Exception('JWT secret not configured.', 500);
    }
    return $secret;
  }

  private function getAuthenticatedUser(bool $requireAdmin = false): User {
    $request = \Drupal::request();
    $jwt = $request->cookies->get('jwt');

    if (!$jwt) {
      throw new \Exception('Not authorized, no token.', 401);
    }

    $decoded = JWT::decode($jwt, new JWTKey($this->getJwtSecret(), 'HS256'));
    $uid = $decoded->uid ?? null;
    $user = User::load($uid);

    if (!$user || !$user->isActive()) {
      throw new \Exception('Invalid or inactive user.', 401);
    }

    if ($requireAdmin && !in_array('administrator', $user->getRoles())) {
      throw new \Exception('Not authorized as admin.', 403);
    }

    return $user;
  }
}
