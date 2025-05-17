<?php

namespace Drupal\custom_api\Controller;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Drupal\node\Entity\Node;
use Drupal\user\Entity\User;
use Drupal\key\Entity\Key;
use Firebase\JWT\JWT;
use Firebase\JWT\Key as JWTKey;

class ProductApiController {

  public function getProducts() {
    $request = \Drupal::request();
    $queryParam = $request->query;
  
    $pageSize = getenv('PAGINATION_LIMIT') ?: 8;
    $page = max(1, (int) $queryParam->get('pageNumber', 1));
    $keyword = $queryParam->get('keyword');
  
    $storage = \Drupal::entityTypeManager()->getStorage('node');
    $query = $storage->getQuery()
      ->accessCheck(TRUE)
      ->condition('type', 'product')
      ->condition('status', 1);
  
    if ($keyword) {
      $query->condition('title', '%' . $keyword . '%', 'LIKE');
    }
  
    $count = $query->count()->execute();
  
    // Rebuild query for actual fetch
    $query = $storage->getQuery()
      ->accessCheck(TRUE)
      ->condition('type', 'product')
      ->condition('status', 1);
  
    if ($keyword) {
      $query->condition('title', '%' . $keyword . '%', 'LIKE');
    }
  
    $nids = $query
      ->range(($page - 1) * $pageSize, $pageSize)
      ->sort('nid', 'DESC')
      ->execute();
  
    $nodes = Node::loadMultiple($nids);
    $products = [];
  
    foreach ($nodes as $node) {
      $products[] = [
        '_id' => $node->id(),
        'name' => $node->getTitle(),
        'brand' => $node->get('field_brand')->value,
        'category' => $node->get('field_category')->value,
        'description' => $node->get('field_description')->value,
        'price' => $node->get('field_price')->value,
        'stock_quantity' => $node->get('field_stock__quantity')->value,
        'rating' => $node->get('field_rating')->value,
        'numReviews' => $node->get('field_num_reviews')->value,
        'image' => $node->get('field_product_image')->entity
          ? \Drupal::service('file_url_generator')->generateAbsoluteString(
              $node->get('field_product_image')->entity->getFileUri()
            )
          : null,
          
      ];
    }
  
    return new JsonResponse([
      'products' => $products,
      'page' => $page,
      'pages' => ceil($count / $pageSize),
    ]);
  }

  public function getTopProducts() {
    $storage = \Drupal::entityTypeManager()->getStorage('node');
    $query = $storage->getQuery()
      ->accessCheck(TRUE)
      ->condition('type', 'product')
      ->condition('status', 1)
      ->sort('field_rating', 'DESC')
      ->range(0, 3);
  
    $nids = $query->execute();
    $nodes = Node::loadMultiple($nids);
  
    $products = [];
  
    foreach ($nodes as $node) {
      $products[] = [
        '_id' => $node->id(),
        'name' => $node->getTitle(),
        'brand' => $node->get('field_brand')->value,
        'category' => $node->get('field_category')->value,
        'description' => $node->get('field_description')->value,
        'price' => $node->get('field_price')->value,
        'stock_quantity' => $node->get('field_stock__quantity')->value,
        'rating' => $node->get('field_rating')->value,
        'numReviews' => $node->get('field_num_reviews')->value,
        'image' => $node->get('field_product_image')->entity
          ? \Drupal::service('file_url_generator')->generateAbsoluteString(
              $node->get('field_product_image')->entity->getFileUri()
            )
          : null,
          
      ];
    }
  
    return new JsonResponse($products);
  }
  
  public function getProductById($id) {
  $node = Node::load($id);


  if ($node && $node->bundle() === 'product' && $node->isPublished()) {
    $reviewsField = $node->get('field_reviews')->value ?? '[]';
    $reviews = json_decode($reviewsField, TRUE);
    $product = [
      '_id' => $node->id(),
      'name' => $node->getTitle(),
      'brand' => $node->get('field_brand')->value,
      'category' => $node->get('field_category')->value,
      'description' => $node->get('field_description')->value,
      'price' => $node->get('field_price')->value,
      'stock_quantity' => $node->get('field_stock__quantity')->value,
      'rating' => $node->get('field_rating')->value,
      'numReviews' => $node->get('field_num_reviews')->value,
      'image' => $node->get('field_product_image')->entity
        ? \Drupal::service('file_url_generator')->generateAbsoluteString(
            $node->get('field_product_image')->entity->getFileUri()
          )
        : null,
      'reviews'=>$reviews
    ];

    return new JsonResponse($product);
  } else {
    return new JsonResponse(['message' => 'Product not found'], 404);
  }
}


public function createReview(Request $request, $id)
 {
  // 1. Auth via JWT cookie
  $jwt = $request->cookies->get('jwt');
  if (!$jwt) {
    return new JsonResponse(['message' => 'Not authorized, no token'], 401);
  }

  $key = Key::load('simple_oauth');
  $secret = $key ? $key->getKeyValue() : '';
  if (!$secret) {
    return new JsonResponse(['message' => 'JWT secret not configured'], 500);
  }

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

  // 2. Load product node
  $node = Node::load($id);
  if (!$node || $node->bundle() !== 'product') {
    return new JsonResponse(['message' => 'Product not found'], 404);
  }

  // 3. Get review data from body
  $data = json_decode($request->getContent(), TRUE);
  $rating = (int) ($data['rating'] ?? 0);
  $comment = $data['comment'] ?? '';

  // 4. Load existing reviews
  $reviewsField = $node->get('field_reviews')->value ?? '[]';
  $reviews = json_decode($reviewsField, TRUE);

  // 5. Check if user already reviewed
  foreach ($reviews as $rev) {
    if ($rev['user_id'] == $user->id()) {
      return new JsonResponse(['message' => 'Product already reviewed'], 400);
    }
  }

  // 6. Add new review
  $reviews[] = [
    '_id' => $user->id(),
    'name' => $user->getDisplayName(),
    'rating' => $rating,
    'comment' => $comment,
    'createdAt' => date('c'),
  ];

  // 7. Recalculate rating
  $numReviews = count($reviews);
  $avgRating = array_sum(array_column($reviews, 'rating')) / $numReviews;

  // 8. Save back to node
  $node->set('field_reviews', json_encode($reviews));
  $node->set('field_rating', $avgRating);
  $node->set('field_num_reviews', $numReviews);
  $node->save();

  return new JsonResponse(['message' => 'Review added'], 201);
}
public function createProduct(Request $request) {
  // Authenticate using JWT
  $jwt = $request->cookies->get('jwt');

  if (!$jwt) {
    return new JsonResponse(['message' => 'Not authorized, no token'], 401);
  }

  $key = Key::load('simple_oauth');
  $secret = $key ? $key->getKeyValue() : '';
  if (!$secret) {
    return new JsonResponse(['message' => 'JWT secret not configured'], 500);
  }

  try {
    $decoded = JWT::decode($jwt, new JWTKey($secret, 'HS256'));
    $uid = $decoded->uid ?? 0;
    $user = User::load($uid);

    if (!$user || !$user->isActive()) {
      return new JsonResponse(['message' => 'Invalid or inactive user'], 401);
    }

    if (!in_array('administrator', $user->getRoles())) {
      return new JsonResponse(['message' => 'Not authorized as admin'], 403);
    }
  } catch (\Exception $e) {
    return new JsonResponse(['message' => 'Token error: ' . $e->getMessage()], 401);
  }

  // Create default product
  $node = Node::create([
    'type' => 'product',
    'title' => 'Sample name',
    'uid' => $user->id(),
    'field_price' => 0,
    'field_brand' => 'Sample brand',
    'field_category' => 'Sample category',
    'field_description' => 'Sample description',
    'field_stock__quantity' => 0,
    'field_rating' => 0,
    'field_num_reviews' => 0,
    'field_product_image' => NULL, // You can set a default image later
  ]);
  $node->save();

  return new JsonResponse([
    '_id' => $node->id(),
    'message' => 'Sample product created',
  ], 201);
}
public function updateProduct(Request $request, $id) {
  // Authenticate via JWT
  $jwt = $request->cookies->get('jwt');
  if (!$jwt) {
    return new JsonResponse(['message' => 'Not authorized, no token'], 401);
  }

  $key = Key::load('simple_oauth');
  $secret = $key ? $key->getKeyValue() : '';
  if (!$secret) {
    return new JsonResponse(['message' => 'JWT secret not configured'], 500);
  }

  try {
    $decoded = JWT::decode($jwt, new JWTKey($secret, 'HS256'));
    $uid = $decoded->uid ?? 0;
    $user = User::load($uid);

    if (!$user || !$user->isActive()) {
      return new JsonResponse(['message' => 'Invalid or inactive user'], 401);
    }

    if (!in_array('administrator', $user->getRoles())) {
      return new JsonResponse(['message' => 'Not authorized as admin'], 403);
    }
  } catch (\Exception $e) {
    return new JsonResponse(['message' => 'Token error: ' . $e->getMessage()], 401);
  }

  // Load product node
  $node = Node::load($id);
  if (!$node || $node->bundle() !== 'product') {
    return new JsonResponse(['message' => 'Product not found'], 404);
  }

  $data = json_decode($request->getContent(), TRUE);

  // Update fields
  $node->setTitle($data['name'] ?? $node->getTitle());
  $node->set('field_price', $data['price'] ?? $node->get('field_price')->value);
  $node->set('field_description', $data['description'] ?? $node->get('field_description')->value);
  $node->set('field_brand', $data['brand'] ?? $node->get('field_brand')->value);
  $node->set('field_category', $data['category'] ?? $node->get('field_category')->value);
  $node->set('field_stock__quantity', $data['countInStock'] ?? $node->get('field_stock__quantity')->value);

  $node->save();

  return new JsonResponse([
    'message' => 'Product updated',
    '_id' => $node->id(),
  ]);
}

public function deleteProduct($id) {
  $node = \Drupal::entityTypeManager()->getStorage('node')->load($id);

  if ($node && $node->bundle() === 'product') {
    $node->delete();
    return new JsonResponse(['message' => 'Product removed']);
  } else {
    return new JsonResponse(['message' => 'Product not found'], 404);
  }
}


}
