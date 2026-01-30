package com.luban.product.controller;

import com.luban.common.entity.Product;
import com.luban.common.repository.ProductRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/products")
public class ProductController {

    private final ProductRepository productRepository;

    public ProductController(ProductRepository productRepository) {
        this.productRepository = productRepository;
    }

    @GetMapping
    @PreAuthorize("hasAnyAuthority('ROLE_USER', 'ROLE_EDITOR', 'ROLE_PRODUCT_ADMIN')")
    public ResponseEntity<List<Product>> getProducts() {
        List<Product> products = productRepository.findAll();
        return ResponseEntity.ok(products);
    }

    @PostMapping
    @PreAuthorize("hasAnyAuthority('ROLE_EDITOR', 'ROLE_PRODUCT_ADMIN')")
    public ResponseEntity<Product> createProduct(@RequestBody Product product) {
        Product saved = productRepository.save(product);
        return ResponseEntity.ok(saved);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('ROLE_EDITOR', 'ROLE_PRODUCT_ADMIN')")
    public ResponseEntity<Product> updateProduct(@PathVariable Long id, @RequestBody Product product) {
        return productRepository.findById(id)
                .map(existing -> {
                    existing.setName(product.getName());
                    return ResponseEntity.ok(productRepository.save(existing));
                })
                .orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('ROLE_EDITOR', 'ROLE_PRODUCT_ADMIN')")
    public ResponseEntity<Void> deleteProduct(@PathVariable Long id) {
        if (productRepository.existsById(id)) {
            productRepository.deleteById(id);
            return ResponseEntity.ok().build();
        }
        return ResponseEntity.notFound().build();
    }
}
