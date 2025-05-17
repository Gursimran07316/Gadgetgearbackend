<?php

namespace Drupal\custom_api\Controller;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Drupal\node\Entity\Node;
use Drupal\user\Entity\User;
use Drupal\key\Entity\Key;
use Firebase\JWT\JWT;
use Firebase\JWT\Key as JWTKey;


class OrderController {

  public function addOrderItems(Request $request) {
    // Get JWT from cookie
    $jwt = $request->cookies->get('jwt');

    if (!$jwt) {
      return new JsonResponse(['message' => 'Not authorized, no token'], 401);
    }

    // Load the secret key from Key module
    $key = Key::load('simple_oauth');
    $secret = $key ? $key->getKeyValue() : '';

    if (!$secret) {
      return new JsonResponse(['message' => 'JWT secret not configured'], 500);
    }

    // Decode and validate JWT
    try {
      $decoded = JWT::decode($jwt, new JWTKey($secret, 'HS256'));
      $uid = $decoded->uid ?? 0;
      $user = User::load($uid);

      if (!$user || !$user->isActive()) {
        return new JsonResponse(['message' => 'Invalid or inactive user'], 401);
      }
    } catch (\Exception $e) {
      return new JsonResponse(['message' => 'Token error: ' . $e->getMessage()], 401);
    }

    // Get POST data
    $data = json_decode($request->getContent(), TRUE);

    $orderItems = $data['orderItems'] ?? [];
    $shippingAddress = $data['shippingAddress'] ?? [];
    $paymentMethod = $data['paymentMethod'] ?? '';

    if (empty($orderItems)) {
      return new JsonResponse(['message' => 'No order items'], 400);
    }

    // Validate products from database
    $product_ids = array_map(fn($item) => $item['_id'], $orderItems);
    $products = \Drupal::entityTypeManager()
      ->getStorage('node')
      ->loadMultiple($product_ids);

    $validatedItems = [];
    $itemsPrice = 0;

    foreach ($orderItems as $item) {
      $product = $products[$item['_id']] ?? null;

      if ($product && $product->bundle() === 'product') {
        $price = (float) $product->get('field_price')->value;
        $qty = (int) $item['qty'];
        $validatedItems[] = [
          'name' => $item['name'],
          'qty' => $qty,
          'price' => $price,
          'image' => $item['image'],
          'product_id' => $item['_id'],
        ];
        $itemsPrice += $price * $qty;
      }
    }

    // Price calculation
    $taxPrice = round($itemsPrice * 0.15, 2);
    $shippingPrice = $itemsPrice > 100 ? 0 : 10;
    $totalPrice = $itemsPrice + $taxPrice + $shippingPrice;

    // Create order node
   
    $order = Node::create([
        'type' => 'order',
        'title' => 'Order for user ' . $user->id(),
        'uid' => $user->id(),
        'field_user' => ['target_id' => $user->id()],
        'field_shipping' => ['value' => json_encode($shippingAddress)],
        'field_order_items' => ['value' => json_encode($validatedItems)],
        'field_payment_method' => ['value' => $paymentMethod],
        'field_items_price' => ['value' => $itemsPrice],
        'field_tax_price' => ['value' => $taxPrice],
        'field_shipping_price' => ['value' => $shippingPrice],
        'field_total_price' => ['value' => $totalPrice],
        'field_is_paid' => ['value' => 0],
        'field_is_delivered' => ['value' => 0],
      ]);
      
      
      
    $order->save();

    // Return response
    return new JsonResponse([
      '_id' => $order->id(),
      'user_id' => $user->id(),
      'items' => $validatedItems,
      'shippingAddress' => $shippingAddress,
      'paymentMethod' => $paymentMethod,
      'itemsPrice' => $itemsPrice,
      'taxPrice' => $taxPrice,
      'shippingPrice' => $shippingPrice,
      'totalPrice' => $totalPrice,
    ], 201);
  }


  public function getMyOrders() {
    $request = \Drupal::request();
    $jwt = $request->cookies->get('jwt');

    if (!$jwt) {
      return new JsonResponse(['message' => 'Not authorized, no token'], 401);
    }

    $key = Key::load('simple_oauth');
    $secret = $key ? $key->getKeyValue() : null;

    if (!$secret) {
      return new JsonResponse(['message' => 'JWT secret missing'], 500);
    }

    try {
        $decoded = JWT::decode($jwt, new JWTKey($secret, 'HS256'));
      $uid = $decoded->uid ?? null;

      if (!$uid) {
        return new JsonResponse(['message' => 'Invalid token'], 401);
      }

      $query = \Drupal::entityTypeManager()->getStorage('node')->getQuery()
        ->condition('type', 'order')
        ->condition('field_user', $uid)
        ->accessCheck(FALSE);  // optionally TRUE for stricter access control

      $nids = $query->execute();
      $orders = Node::loadMultiple($nids);

      $output = [];

      foreach ($orders as $order) {
        $shipping = json_decode($order->get('field_shipping')->value, TRUE);
        $items = json_decode($order->get('field_order_items')->value ?? '[]', TRUE); // Assuming you save items as JSON in a long text field
      
        $output[] = [
          '_id' => $order->id(),
          'user' => $order->getOwnerId(),
          'shippingAddress' => $shipping,
          'orderItems' => $items,
          'paymentMethod' => $order->get('field_payment_method')->value,
          'itemsPrice' => (float) $order->get('field_items_price')->value,
          'taxPrice' => (float) $order->get('field_tax_price')->value,
          'shippingPrice' => (float) $order->get('field_shipping_price')->value,
          'totalPrice' => (float) $order->get('field_total_price')->value,
          'isPaid' => (bool) $order->get('field_is_paid')->value,
          'isDelivered' => (bool) $order->get('field_is_delivered')->value,
          'createdAt' => date('c', $order->getCreatedTime()),
          'updatedAt' => date('c', $order->getChangedTime()),
        ];
    }

      return new JsonResponse($output);

    } catch (\Exception $e) {
        return new JsonResponse([
          'message' => 'Token invalid or expired: ' . $e->getMessage()
        ], 403);
      }
      
  }

  public function getOrderById($id) {
    $request = \Drupal::request();
    $jwt = $request->cookies->get('jwt');
  
    if (!$jwt) {
      return new JsonResponse(['message' => 'Not authorized, no token'], 401);
    }
  
    $key = Key::load('simple_oauth');
    $secret = $key ? $key->getKeyValue() : null;
  
    if (!$secret) {
      return new JsonResponse(['message' => 'JWT secret missing'], 500);
    }
  
    try {
      $decoded = JWT::decode($jwt, new JWTKey($secret, 'HS256'));
      $uid = $decoded->uid ?? null;
  
      if (!$uid) {
        return new JsonResponse(['message' => 'Invalid token'], 401);
      }
  
      $order = Node::load($id);
  
      if (!$order || $order->bundle() !== 'order') {
        return new JsonResponse(['message' => 'Order not found'], 404);
      }
  
      // Allow only owner or admin
      $owner_id = $order->getOwnerId();
      if ($owner_id != $uid && !User::load($uid)->hasPermission('administer nodes')) {
        return new JsonResponse(['message' => 'Unauthorized access'], 403);
      }
  
      $shipping = json_decode($order->get('field_shipping')->value, TRUE);
      $items = json_decode($order->get('field_order_items')->value ?? '[]', TRUE);
  
      $user = User::load($owner_id);
  
      return new JsonResponse([
        '_id' => $order->id(),
        'user' => [
          '_id' => $user->id(),
          'name' => $user->getDisplayName(),
          'email' => $user->getEmail(),
        ],
        'shippingAddress' => $shipping,
        'orderItems' => $items,
        'paymentMethod' => $order->get('field_payment_method')->value,
        'itemsPrice' => (float) $order->get('field_items_price')->value,
        'taxPrice' => (float) $order->get('field_tax_price')->value,
        'shippingPrice' => (float) $order->get('field_shipping_price')->value,
        'totalPrice' => (float) $order->get('field_total_price')->value,
        'isPaid' => (bool) $order->get('field_is_paid')->value,
        'isDelivered' => (bool) $order->get('field_is_delivered')->value,
        'createdAt' => date('c', $order->getCreatedTime()),
        'updatedAt' => date('c', $order->getChangedTime()),
      ]);
  
    } catch (\Exception $e) {
      return new JsonResponse(['message' => 'Token error: ' . $e->getMessage()], 403);
    }
  }
  public function getAllOrders() {
    $request = \Drupal::request();
    $jwt = $request->cookies->get('jwt');
  
    if (!$jwt) {
      return new JsonResponse(['message' => 'Not authorized, no token'], 401);
    }
  
    $key = Key::load('simple_oauth');
    $secret = $key ? $key->getKeyValue() : null;
  
    if (!$secret) {
      return new JsonResponse(['message' => 'JWT secret missing'], 500);
    }
  
    try {
      $decoded = JWT::decode($jwt, new JWTKey($secret, 'HS256'));
      $uid = $decoded->uid ?? null;
      $user = User::load($uid);
  
      if (!$user || !in_array('administrator', $user->getRoles())) {
        return new JsonResponse(['message' => 'Admin access required'], 403);
      }
  
      $query = \Drupal::entityTypeManager()->getStorage('node')->getQuery()
        ->accessCheck(FALSE)
        ->condition('type', 'order');
  
      $nids = $query->execute();
      $orders = Node::loadMultiple($nids);
  
      $output = [];
  
      foreach ($orders as $order) {
        $owner = $order->getOwner();
        $output[] = [
          '_id' => $order->id(),
          'user' => [
            '_id' => $owner->id(),
            'name' => $owner->getDisplayName(),
          ],
          'isPaid' => (bool) $order->get('field_is_paid')->value,
          'isDelivered' => (bool) $order->get('field_is_delivered')->value,
          'totalPrice' => (float) $order->get('field_total_price')->value,
          'createdAt' => date('c', $order->getCreatedTime()),
        ];
      }
  
      return new JsonResponse($output);
  
    } catch (\Exception $e) {
      return new JsonResponse(['message' => 'Token error: ' . $e->getMessage()], 403);
    }
  }
  public function markOrderDelivered($id) {
    $request = \Drupal::request();
    $jwt = $request->cookies->get('jwt');
  
    if (!$jwt) {
      return new JsonResponse(['message' => 'Not authorized, no token'], 401);
    }
  
    $key = Key::load('simple_oauth');
    $secret = $key ? $key->getKeyValue() : null;
  
    if (!$secret) {
      return new JsonResponse(['message' => 'JWT secret missing'], 500);
    }
  
    try {
      $decoded = JWT::decode($jwt, new JWTKey($secret, 'HS256'));
      $uid = $decoded->uid ?? null;
      $user = User::load($uid);
  
      if (!$user || !in_array('administrator', $user->getRoles())) {
        return new JsonResponse(['message' => 'Admin access required'], 403);
      }
  
      $order = Node::load($id);
  
      if (!$order || $order->bundle() !== 'order') {
        return new JsonResponse(['message' => 'Order not found'], 404);
      }
  
      $order->set('field_is_delivered', 1);
      $order->save();
  
      return new JsonResponse(['message' => 'Order marked as delivered']);
  
    } catch (\Exception $e) {
      return new JsonResponse(['message' => 'Token error: ' . $e->getMessage()], 403);
    }
  }
    
  
}
