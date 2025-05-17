<?php

namespace Drupal\custom_api\Controller;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Cookie;
use Drupal\Core\Controller\ControllerBase;
use Drupal\user\Entity\User;
use Drupal\key\Entity\Key;
use Firebase\JWT\JWT;

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

    // Load JWT secret from Key module (make sure 'simple_oauth' key exists)
    $key = Key::load('simple_oauth');
    $secret = $key ? $key->getKeyValue() : '';

    if (!$secret) {
      return new JsonResponse(['message' => 'JWT secret not configured.'], 500);
    }

    // Create JWT token
    $payload = [
      'uid' => $user->id(),
      'name' => $user->getAccountName(),
      'email' => $user->getEmail(),
      'exp' => time() + 30 * 24 * 60 * 60, // 30 days
    ];

    $jwt = JWT::encode($payload, $secret, 'HS256');

    // Create response
    $response = new JsonResponse([
        '_id' => $user->id(),
        'name' => $user->getAccountName(),
        'email' => $user->getEmail(),
        'isAdmin' => in_array('administrator', $user->getRoles()),

    ]);

    // Set JWT as HTTP-only cookie
    $cookie = new Cookie(
      'jwt',                     // name
      $jwt,                      // value
      time() + 30 * 24 * 60 * 60, // expires in 30 days
      '/',                       // path
      null,                      // domain
      false,                     // secure (set to true on HTTPS)
      true,                      // httpOnly
      false,                     // raw
      'Strict'                   // sameSite
    );

    $response->headers->setCookie($cookie);
    return $response;
  }

  public function logoutUser(Request $request) {
    $response = new JsonResponse(['message' => 'Logged out successfully.'], 200);
  
    // Clear the JWT cookie by setting its expiration to the past
    $response->headers->clearCookie('jwt', '/', null, false, true, false, 'Strict');
  
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
  
    // Create new user
    $user = User::create([
      'name' => $name,
      'mail' => $email,
      'pass' => $password,
      'status' => 1,
    ]);
    $user->enforceIsNew();
    $user->save();
  
    // JWT secret
    $key = Key::load('simple_oauth');
    $secret = $key ? $key->getKeyValue() : '';
    if (!$secret) {
      return new JsonResponse(['message' => 'JWT secret not configured.'], 500);
    }
  
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
  
    $response->headers->setCookie(
      new \Symfony\Component\HttpFoundation\Cookie(
        'jwt',
        $jwt,
        time() + 30 * 24 * 60 * 60,
        '/',
        null,
        false,
        true,
        false,
        'Strict'
      )
    );
  
    return $response;
  }
  private function getAuthenticatedAdmin() {
    $request = \Drupal::request();
    $jwt = $request->cookies->get('jwt');
  
    if (!$jwt) {
      throw new \Exception('Not authorized, no token', 401);
    }
  
    $key = \Drupal\key\Entity\Key::load('simple_oauth');
    $secret = $key ? $key->getKeyValue() : '';
    if (!$secret) {
      throw new \Exception('JWT secret not configured', 500);
    }
  
    $decoded = \Firebase\JWT\JWT::decode($jwt, new \Firebase\JWT\Key($secret, 'HS256'));
    $uid = $decoded->uid ?? null;
    $user = \Drupal\user\Entity\User::load($uid);
  
    if (!$user || !$user->isActive() || !in_array('administrator', $user->getRoles())) {
      throw new \Exception('Not authorized as admin', 403);
    }
  
    return $user;
  }
  public function getUsers() {
    try {
      $this->getAuthenticatedAdmin();
  
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
      $this->getAuthenticatedAdmin();
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
      $this->getAuthenticatedAdmin();
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
      $this->getAuthenticatedAdmin();
  
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
      
}
