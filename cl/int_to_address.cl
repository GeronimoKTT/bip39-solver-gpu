
__kernel void int_to_address(ulong mnemonic_start_hi, ulong mnemonic_start_lo, __global const ulong * target_prefixes, __global const uchar * target_addresses, uint num_targets, __global uchar * target_mnemonic, __global uchar * found_mnemonic) {
  ulong idx = get_global_id(0);

  ulong mnemonic_lo = mnemonic_start_lo + idx;
  ulong mnemonic_hi = mnemonic_start_hi;

  uchar bytes[16];
  bytes[15] = mnemonic_lo & 0xFF;
  bytes[14] = (mnemonic_lo >> 8) & 0xFF;
  bytes[13] = (mnemonic_lo >> 16) & 0xFF;
  bytes[12] = (mnemonic_lo >> 24) & 0xFF;
  bytes[11] = (mnemonic_lo >> 32) & 0xFF;
  bytes[10] = (mnemonic_lo >> 40) & 0xFF;
  bytes[9] = (mnemonic_lo >> 48) & 0xFF;
  bytes[8] = (mnemonic_lo >> 56) & 0xFF;
  
  bytes[7] = mnemonic_hi & 0xFF;
  bytes[6] = (mnemonic_hi >> 8) & 0xFF;
  bytes[5] = (mnemonic_hi >> 16) & 0xFF;
  bytes[4] = (mnemonic_hi >> 24) & 0xFF;
  bytes[3] = (mnemonic_hi >> 32) & 0xFF;
  bytes[2] = (mnemonic_hi >> 40) & 0xFF;
  bytes[1] = (mnemonic_hi >> 48) & 0xFF;
  bytes[0] = (mnemonic_hi >> 56) & 0xFF;

  uchar mnemonic_hash[32];
  sha256(&bytes, 16, &mnemonic_hash);
  uchar checksum = (mnemonic_hash[0] >> 4) & ((1 << 4)-1);
  
  ushort indices[12];
  indices[0] = (mnemonic_hi >> 53) & 2047;
  indices[1] = (mnemonic_hi >> 42) & 2047;
  indices[2] = (mnemonic_hi >> 31) & 2047;
  indices[3] = (mnemonic_hi >> 20) & 2047;
  indices[4] = (mnemonic_hi >> 9)  & 2047;
  indices[5] = ((mnemonic_hi & ((1 << 9)-1)) << 2) | ((mnemonic_lo >> 62) & 3);
  indices[6] = (mnemonic_lo >> 51) & 2047;
  indices[7] = (mnemonic_lo >> 40) & 2047;
  indices[8] = (mnemonic_lo >> 29) & 2047;
  indices[9] = (mnemonic_lo >> 18) & 2047;
  indices[10] = (mnemonic_lo >> 7) & 2047;
  indices[11] = ((mnemonic_lo & ((1 << 7)-1)) << 4) | checksum;

  uchar mnemonic[180] = {0};
  uchar mnemonic_length = 11 + word_lengths[indices[0]] + word_lengths[indices[1]] + word_lengths[indices[2]] + word_lengths[indices[3]] + word_lengths[indices[4]] + word_lengths[indices[5]] + word_lengths[indices[6]] + word_lengths[indices[7]] + word_lengths[indices[8]] + word_lengths[indices[9]] + word_lengths[indices[10]] + word_lengths[indices[11]];
  int mnemonic_index = 0;
  
  for (int i=0; i < 12; i++) {
    int word_index = indices[i];
    int word_length = word_lengths[word_index];
    
    for(int j=0;j<word_length;j++) {
      mnemonic[mnemonic_index] = words[word_index][j];
      mnemonic_index++;
    }
    mnemonic[mnemonic_index] = 32;
    mnemonic_index++;
  }
  mnemonic[mnemonic_index - 1] = 0;

  // Fast Midstate PBKDF2 HMAC-SHA512 (pre-calculated salt state & single block transforms per round)
  uchar seed[64] = { 0 };
  pbkdf2_hmac_sha512_fast(mnemonic, mnemonic_length, seed);

  uchar network = BITCOIN_MAINNET;
  extended_private_key_t master_private;
  extended_public_key_t master_public;

  new_master_from_seed(network, &seed, &master_private);
  public_from_private(&master_private, &master_public);

  uchar serialized_master_public[33];
  serialized_public_key(&master_public, &serialized_master_public);
  extended_private_key_t target_key;
  extended_public_key_t target_public_key;
  hardened_private_child_from_private(&master_private, &target_key, 49);
  hardened_private_child_from_private(&target_key, &target_key, 0);
  hardened_private_child_from_private(&target_key, &target_key, 0);
  normal_private_child_from_private(&target_key, &target_key, 0);
  normal_private_child_from_private(&target_key, &target_key, 0);
  public_from_private(&target_key, &target_public_key);

  uchar raw_address[25] = {0};
  p2shwpkh_address_for_public_key(&target_public_key, &raw_address);

  ulong key = ((ulong)raw_address[1] << 56) |
              ((ulong)raw_address[2] << 48) |
              ((ulong)raw_address[3] << 40) |
              ((ulong)raw_address[4] << 32) |
              ((ulong)raw_address[5] << 24) |
              ((ulong)raw_address[6] << 16) |
              ((ulong)raw_address[7] << 8)  |
              (ulong)raw_address[8];

  bool found_target = 0;
  int low = 0;
  int high = (int)num_targets - 1;

  while (low <= high) {
    int mid = low + ((high - low) >> 1);
    ulong mid_val = target_prefixes[mid];

    if (mid_val == key) {
      bool match = 1;
      __global const uchar * curr_target = &target_addresses[mid * 25];
      for (int i = 0; i < 25; i++) {
        if (raw_address[i] != curr_target[i]) {
          match = 0;
          break;
        }
      }
      if (match == 1) {
        found_target = 1;
        break;
      }

      int l = mid - 1;
      while (l >= 0 && target_prefixes[l] == key) {
        match = 1;
        curr_target = &target_addresses[l * 25];
        for (int i = 0; i < 25; i++) {
          if (raw_address[i] != curr_target[i]) { match = 0; break; }
        }
        if (match == 1) { found_target = 1; break; }
        l--;
      }
      if (found_target == 1) break;

      int r = mid + 1;
      while (r < (int)num_targets && target_prefixes[r] == key) {
        match = 1;
        curr_target = &target_addresses[r * 25];
        for (int i = 0; i < 25; i++) {
          if (raw_address[i] != curr_target[i]) { match = 0; break; }
        }
        if (match == 1) { found_target = 1; break; }
        r++;
      }
      if (found_target == 1) break;

      break;
    } else if (mid_val < key) {
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }

  if(found_target == 1) {
    found_mnemonic[0] = 0x01;
    for(int i=0; i<mnemonic_index; i++) {
      target_mnemonic[i] = mnemonic[i];
    }
  }
}

__kernel void int_to_address_perm(__global const ulong * hi_list, __global const ulong * lo_list, __global const ulong * target_prefixes, __global const uchar * target_addresses, uint num_targets, __global uchar * target_mnemonic, __global uchar * found_mnemonic) {
  ulong idx = get_global_id(0);

  ulong mnemonic_lo = lo_list[idx];
  ulong mnemonic_hi = hi_list[idx];

  uchar bytes[16];
  bytes[15] = mnemonic_lo & 0xFF;
  bytes[14] = (mnemonic_lo >> 8) & 0xFF;
  bytes[13] = (mnemonic_lo >> 16) & 0xFF;
  bytes[12] = (mnemonic_lo >> 24) & 0xFF;
  bytes[11] = (mnemonic_lo >> 32) & 0xFF;
  bytes[10] = (mnemonic_lo >> 40) & 0xFF;
  bytes[9] = (mnemonic_lo >> 48) & 0xFF;
  bytes[8] = (mnemonic_lo >> 56) & 0xFF;
  
  bytes[7] = mnemonic_hi & 0xFF;
  bytes[6] = (mnemonic_hi >> 8) & 0xFF;
  bytes[5] = (mnemonic_hi >> 16) & 0xFF;
  bytes[4] = (mnemonic_hi >> 24) & 0xFF;
  bytes[3] = (mnemonic_hi >> 32) & 0xFF;
  bytes[2] = (mnemonic_hi >> 40) & 0xFF;
  bytes[1] = (mnemonic_hi >> 48) & 0xFF;
  bytes[0] = (mnemonic_hi >> 56) & 0xFF;

  uchar mnemonic_hash[32];
  sha256(&bytes, 16, &mnemonic_hash);
  uchar checksum = (mnemonic_hash[0] >> 4) & ((1 << 4)-1);
  
  ushort indices[12];
  indices[0] = (mnemonic_hi >> 53) & 2047;
  indices[1] = (mnemonic_hi >> 42) & 2047;
  indices[2] = (mnemonic_hi >> 31) & 2047;
  indices[3] = (mnemonic_hi >> 20) & 2047;
  indices[4] = (mnemonic_hi >> 9)  & 2047;
  indices[5] = ((mnemonic_hi & ((1 << 9)-1)) << 2) | ((mnemonic_lo >> 62) & 3);
  indices[6] = (mnemonic_lo >> 51) & 2047;
  indices[7] = (mnemonic_lo >> 40) & 2047;
  indices[8] = (mnemonic_lo >> 29) & 2047;
  indices[9] = (mnemonic_lo >> 18) & 2047;
  indices[10] = (mnemonic_lo >> 7) & 2047;
  indices[11] = ((mnemonic_lo & ((1 << 7)-1)) << 4) | checksum;

  uchar mnemonic[180] = {0};
  uchar mnemonic_length = 11 + word_lengths[indices[0]] + word_lengths[indices[1]] + word_lengths[indices[2]] + word_lengths[indices[3]] + word_lengths[indices[4]] + word_lengths[indices[5]] + word_lengths[indices[6]] + word_lengths[indices[7]] + word_lengths[indices[8]] + word_lengths[indices[9]] + word_lengths[indices[10]] + word_lengths[indices[11]];
  int mnemonic_index = 0;
  
  for (int i=0; i < 12; i++) {
    int word_index = indices[i];
    int word_length = word_lengths[word_index];
    
    for(int j=0;j<word_length;j++) {
      mnemonic[mnemonic_index] = words[word_index][j];
      mnemonic_index++;
    }
    mnemonic[mnemonic_index] = 32;
    mnemonic_index++;
  }
  mnemonic[mnemonic_index - 1] = 0;

  // Fast Midstate PBKDF2 HMAC-SHA512
  uchar seed[64] = { 0 };
  pbkdf2_hmac_sha512_fast(mnemonic, mnemonic_length, seed);

  uchar network = BITCOIN_MAINNET;
  extended_private_key_t master_private;
  extended_public_key_t master_public;

  new_master_from_seed(network, &seed, &master_private);
  public_from_private(&master_private, &master_public);

  uchar serialized_master_public[33];
  serialized_public_key(&master_public, &serialized_master_public);
  extended_private_key_t target_key;
  extended_public_key_t target_public_key;
  hardened_private_child_from_private(&master_private, &target_key, 49);
  hardened_private_child_from_private(&target_key, &target_key, 0);
  hardened_private_child_from_private(&target_key, &target_key, 0);
  normal_private_child_from_private(&target_key, &target_key, 0);
  normal_private_child_from_private(&target_key, &target_key, 0);
  public_from_private(&target_key, &target_public_key);

  uchar raw_address[25] = {0};
  p2shwpkh_address_for_public_key(&target_public_key, &raw_address);

  ulong key = ((ulong)raw_address[1] << 56) |
              ((ulong)raw_address[2] << 48) |
              ((ulong)raw_address[3] << 40) |
              ((ulong)raw_address[4] << 32) |
              ((ulong)raw_address[5] << 24) |
              ((ulong)raw_address[6] << 16) |
              ((ulong)raw_address[7] << 8)  |
              (ulong)raw_address[8];

  bool found_target = 0;
  int low = 0;
  int high = (int)num_targets - 1;

  while (low <= high) {
    int mid = low + ((high - low) >> 1);
    ulong mid_val = target_prefixes[mid];

    if (mid_val == key) {
      bool match = 1;
      __global const uchar * curr_target = &target_addresses[mid * 25];
      for (int i = 0; i < 25; i++) {
        if (raw_address[i] != curr_target[i]) {
          match = 0;
          break;
        }
      }
      if (match == 1) {
        found_target = 1;
        break;
      }

      int l = mid - 1;
      while (l >= 0 && target_prefixes[l] == key) {
        match = 1;
        curr_target = &target_addresses[l * 25];
        for (int i = 0; i < 25; i++) {
          if (raw_address[i] != curr_target[i]) { match = 0; break; }
        }
        if (match == 1) { found_target = 1; break; }
        l--;
      }
      if (found_target == 1) break;

      int r = mid + 1;
      while (r < (int)num_targets && target_prefixes[r] == key) {
        match = 1;
        curr_target = &target_addresses[r * 25];
        for (int i = 0; i < 25; i++) {
          if (raw_address[i] != curr_target[i]) { match = 0; break; }
        }
        if (match == 1) { found_target = 1; break; }
        r++;
      }
      if (found_target == 1) break;

      break;
    } else if (mid_val < key) {
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }

  if(found_target == 1) {
    found_mnemonic[0] = 0x01;
    for(int i=0; i<mnemonic_index; i++) {
      target_mnemonic[i] = mnemonic[i];
    }
  }
}

__kernel void get_address_for_entropy(ulong mnemonic_hi, ulong mnemonic_lo, __global uchar * out_address) {
  uchar bytes[16];
  bytes[15] = mnemonic_lo & 0xFF;
  bytes[14] = (mnemonic_lo >> 8) & 0xFF;
  bytes[13] = (mnemonic_lo >> 16) & 0xFF;
  bytes[12] = (mnemonic_lo >> 24) & 0xFF;
  bytes[11] = (mnemonic_lo >> 32) & 0xFF;
  bytes[10] = (mnemonic_lo >> 40) & 0xFF;
  bytes[9] = (mnemonic_lo >> 48) & 0xFF;
  bytes[8] = (mnemonic_lo >> 56) & 0xFF;
  
  bytes[7] = mnemonic_hi & 0xFF;
  bytes[6] = (mnemonic_hi >> 8) & 0xFF;
  bytes[5] = (mnemonic_hi >> 16) & 0xFF;
  bytes[4] = (mnemonic_hi >> 24) & 0xFF;
  bytes[3] = (mnemonic_hi >> 32) & 0xFF;
  bytes[2] = (mnemonic_hi >> 40) & 0xFF;
  bytes[1] = (mnemonic_hi >> 48) & 0xFF;
  bytes[0] = (mnemonic_hi >> 56) & 0xFF;

  uchar mnemonic_hash[32];
  sha256(&bytes, 16, &mnemonic_hash);
  uchar checksum = (mnemonic_hash[0] >> 4) & ((1 << 4)-1);
  
  ushort indices[12];
  indices[0] = (mnemonic_hi >> 53) & 2047;
  indices[1] = (mnemonic_hi >> 42) & 2047;
  indices[2] = (mnemonic_hi >> 31) & 2047;
  indices[3] = (mnemonic_hi >> 20) & 2047;
  indices[4] = (mnemonic_hi >> 9)  & 2047;
  indices[5] = ((mnemonic_hi & ((1 << 9)-1)) << 2) | ((mnemonic_lo >> 62) & 3);
  indices[6] = (mnemonic_lo >> 51) & 2047;
  indices[7] = (mnemonic_lo >> 40) & 2047;
  indices[8] = (mnemonic_lo >> 29) & 2047;
  indices[9] = (mnemonic_lo >> 18) & 2047;
  indices[10] = (mnemonic_lo >> 7) & 2047;
  indices[11] = ((mnemonic_lo & ((1 << 7)-1)) << 4) | checksum;

  uchar mnemonic[180] = {0};
  uchar mnemonic_length = 11 + word_lengths[indices[0]] + word_lengths[indices[1]] + word_lengths[indices[2]] + word_lengths[indices[3]] + word_lengths[indices[4]] + word_lengths[indices[5]] + word_lengths[indices[6]] + word_lengths[indices[7]] + word_lengths[indices[8]] + word_lengths[indices[9]] + word_lengths[indices[10]] + word_lengths[indices[11]];
  int mnemonic_index = 0;
  
  for (int i=0; i < 12; i++) {
    int word_index = indices[i];
    int word_length = word_lengths[word_index];
    
    for(int j=0;j<word_length;j++) {
      mnemonic[mnemonic_index] = words[word_index][j];
      mnemonic_index++;
    }
    mnemonic[mnemonic_index] = 32;
    mnemonic_index++;
  }
  mnemonic[mnemonic_index - 1] = 0;

  // Fast Midstate PBKDF2 HMAC-SHA512
  uchar seed[64] = { 0 };
  pbkdf2_hmac_sha512_fast(mnemonic, mnemonic_length, seed);

  uchar network = BITCOIN_MAINNET;
  extended_private_key_t master_private;
  extended_public_key_t master_public;

  new_master_from_seed(network, &seed, &master_private);
  public_from_private(&master_private, &master_public);

  uchar serialized_master_public[33];
  serialized_public_key(&master_public, &serialized_master_public);
  extended_private_key_t target_key;
  extended_public_key_t target_public_key;
  hardened_private_child_from_private(&master_private, &target_key, 49);
  hardened_private_child_from_private(&target_key, &target_key, 0);
  hardened_private_child_from_private(&target_key, &target_key, 0);
  normal_private_child_from_private(&target_key, &target_key, 0);
  normal_private_child_from_private(&target_key, &target_key, 0);
  public_from_private(&target_key, &target_public_key);

  p2shwpkh_address_for_public_key(&target_public_key, out_address);
}

constant ulong FACTORIALS_TABLE[13] = {
    1UL, 1UL, 2UL, 6UL, 24UL, 120UL, 720UL, 5040UL, 40320UL, 362880UL, 3628800UL, 39916800UL, 479001600UL
};

inline ulong count_multiset_perms_gpu(const uchar counts[], uchar num_unique, uchar remaining_len) {
    ulong den = 1UL;
    for (uchar i = 0; i < 12; i++) {
        if (i < num_unique) {
            den *= FACTORIALS_TABLE[counts[i]];
        }
    }
    return FACTORIALS_TABLE[remaining_len] / den;
}

inline void unrank_multiset_perm_gpu(
    ulong perm_rank,
    const ushort local_unique[12],
    const uchar local_counts[12],
    uchar num_unique,
    ushort out_indices[12]
) {
    uchar counts[12];
    for (uchar i = 0; i < 12; i++) {
        counts[i] = (i < num_unique) ? local_counts[i] : 0;
    }

    for (uchar slot = 0; slot < 12; slot++) {
        uchar remaining_len = 11 - slot;
        for (uchar u = 0; u < 12; u++) {
            if (u >= num_unique || counts[u] == 0) continue;

            counts[u]--;
            ulong S = count_multiset_perms_gpu(counts, num_unique, remaining_len);
            if (perm_rank < S) {
                out_indices[slot] = local_unique[u];
                break;
            } else {
                perm_rank -= S;
                counts[u]++;
            }
        }
    }
}

__kernel void int_to_address_unordered_wildcard(
    ulong combination_offset,
    __global const ushort * unique_elements,
    __global const uchar * original_counts,
    uchar num_unique,
    uint num_wildcards,
    __global const ulong * target_prefixes,
    __global const uchar * target_addresses,
    uint num_targets,
    __global uchar * target_mnemonic,
    __global uchar * found_mnemonic
) {
    ulong idx = get_global_id(0);
    ulong combination_idx = combination_offset + idx;

    ushort local_unique[12];
    uchar local_counts[12];
    for (uchar u = 0; u < num_unique; u++) {
        local_unique[u] = unique_elements[u];
        local_counts[u] = original_counts[u];
    }

    ulong num_wildcard_combos = 1UL;
    for (uint w = 0; w < num_wildcards; w++) {
        num_wildcard_combos *= 2048UL;
    }

    ulong perm_rank = combination_idx / num_wildcard_combos;
    ulong wildcard_composite = combination_idx % num_wildcard_combos;

    ushort indices[12];
    unrank_multiset_perm_gpu(perm_rank, local_unique, local_counts, num_unique, indices);

    ulong w_temp = wildcard_composite;
    for (uchar i = 0; i < 12; i++) {
        if (indices[i] == 0xFFFF) {
            indices[i] = (ushort)(w_temp % 2048UL);
            w_temp /= 2048UL;
        }
    }

    ulong mnemonic_hi = ((ulong)indices[0] << 53) |
                        ((ulong)indices[1] << 42) |
                        ((ulong)indices[2] << 31) |
                        ((ulong)indices[3] << 20) |
                        ((ulong)indices[4] << 9)  |
                        ((ulong)indices[5] >> 2);

    ulong mnemonic_lo = (((ulong)indices[5] & 3UL) << 62) |
                        ((ulong)indices[6] << 51) |
                        ((ulong)indices[7] << 40) |
                        ((ulong)indices[8] << 29) |
                        ((ulong)indices[9] << 18) |
                        ((ulong)indices[10] << 7) |
                        ((ulong)indices[11] >> 4);

    uchar bytes[16];
    bytes[15] = mnemonic_lo & 0xFF;
    bytes[14] = (mnemonic_lo >> 8) & 0xFF;
    bytes[13] = (mnemonic_lo >> 16) & 0xFF;
    bytes[12] = (mnemonic_lo >> 24) & 0xFF;
    bytes[11] = (mnemonic_lo >> 32) & 0xFF;
    bytes[10] = (mnemonic_lo >> 40) & 0xFF;
    bytes[9] = (mnemonic_lo >> 48) & 0xFF;
    bytes[8] = (mnemonic_lo >> 56) & 0xFF;

    bytes[7] = mnemonic_hi & 0xFF;
    bytes[6] = (mnemonic_hi >> 8) & 0xFF;
    bytes[5] = (mnemonic_hi >> 16) & 0xFF;
    bytes[4] = (mnemonic_hi >> 24) & 0xFF;
    bytes[3] = (mnemonic_hi >> 32) & 0xFF;
    bytes[2] = (mnemonic_hi >> 40) & 0xFF;
    bytes[1] = (mnemonic_hi >> 48) & 0xFF;
    bytes[0] = (mnemonic_hi >> 56) & 0xFF;

    uchar mnemonic_hash[32];
    sha256(&bytes, 16, &mnemonic_hash);
    uchar expected_checksum = (mnemonic_hash[0] >> 4) & 0x0F;
    uchar actual_checksum = (uchar)(indices[11] & 0x0F);

    if (expected_checksum != actual_checksum) {
        return;
    }

    uchar mnemonic[180] = {0};
    uchar mnemonic_length = 11 + word_lengths[indices[0]] + word_lengths[indices[1]] + word_lengths[indices[2]] + word_lengths[indices[3]] + word_lengths[indices[4]] + word_lengths[indices[5]] + word_lengths[indices[6]] + word_lengths[indices[7]] + word_lengths[indices[8]] + word_lengths[indices[9]] + word_lengths[indices[10]] + word_lengths[indices[11]];
    int mnemonic_index = 0;

    for (int i = 0; i < 12; i++) {
        int word_index = indices[i];
        int word_length = word_lengths[word_index];

        for (int j = 0; j < word_length; j++) {
            mnemonic[mnemonic_index] = words[word_index][j];
            mnemonic_index++;
        }
        mnemonic[mnemonic_index] = 32;
        mnemonic_index++;
    }
    mnemonic[mnemonic_index - 1] = 0;

    // Fast Midstate PBKDF2 HMAC-SHA512
    uchar seed[64] = { 0 };
    pbkdf2_hmac_sha512_fast(mnemonic, mnemonic_length, seed);

    uchar network = BITCOIN_MAINNET;
    extended_private_key_t master_private;
    extended_public_key_t master_public;

    new_master_from_seed(network, &seed, &master_private);
    public_from_private(&master_private, &master_public);

    uchar serialized_master_public[33];
    serialized_public_key(&master_public, &serialized_master_public);
    extended_private_key_t target_key;
    extended_public_key_t target_public_key;
    hardened_private_child_from_private(&master_private, &target_key, 49);
    hardened_private_child_from_private(&target_key, &target_key, 0);
    hardened_private_child_from_private(&target_key, &target_key, 0);
    normal_private_child_from_private(&target_key, &target_key, 0);
    normal_private_child_from_private(&target_key, &target_key, 0);
    public_from_private(&target_key, &target_public_key);

    uchar raw_address[25] = {0};
    p2shwpkh_address_for_public_key(&target_public_key, &raw_address);

    ulong key = ((ulong)raw_address[1] << 56) |
                ((ulong)raw_address[2] << 48) |
                ((ulong)raw_address[3] << 40) |
                ((ulong)raw_address[4] << 32) |
                ((ulong)raw_address[5] << 24) |
                ((ulong)raw_address[6] << 16) |
                ((ulong)raw_address[7] << 8)  |
                (ulong)raw_address[8];

    bool found_target = 0;
    int low = 0;
    int high = (int)num_targets - 1;

    while (low <= high) {
        int mid = low + ((high - low) >> 1);
        ulong mid_val = target_prefixes[mid];

        if (mid_val == key) {
            bool match = 1;
            __global const uchar * curr_target = &target_addresses[mid * 25];
            for (int i = 0; i < 25; i++) {
                if (raw_address[i] != curr_target[i]) {
                    match = 0;
                    break;
                }
            }
            if (match == 1) {
                found_target = 1;
                break;
            }

            int l = mid - 1;
            while (l >= 0 && target_prefixes[l] == key) {
                match = 1;
                curr_target = &target_addresses[l * 25];
                for (int i = 0; i < 25; i++) {
                    if (raw_address[i] != curr_target[i]) { match = 0; break; }
                }
                if (match == 1) { found_target = 1; break; }
                l--;
            }
            if (found_target == 1) break;

            int r = mid + 1;
            while (r < (int)num_targets && target_prefixes[r] == key) {
                match = 1;
                curr_target = &target_addresses[r * 25];
                for (int i = 0; i < 25; i++) {
                    if (raw_address[i] != curr_target[i]) { match = 0; break; }
                }
                if (match == 1) { found_target = 1; break; }
                r++;
            }
            if (found_target == 1) break;

            break;
        } else if (mid_val < key) {
            low = mid + 1;
        } else {
            high = mid - 1;
        }
    }

    if (found_target == 1) {
        found_mnemonic[0] = 0x01;
        for (int i = 0; i < mnemonic_index; i++) {
            target_mnemonic[i] = mnemonic[i];
        }
    }
}

__kernel void filter_unordered_wildcard_checksum(
    ulong combination_offset,
    __global const ushort * unique_elements,
    __global const uchar * original_counts,
    uchar num_unique,
    uint num_wildcards,
    __global ulong * valid_hi_list,
    __global ulong * valid_lo_list,
    __global uint * valid_count
) {
    ulong idx = get_global_id(0);
    ulong combination_idx = combination_offset + idx;

    ushort local_unique[12];
    uchar local_counts[12];
    for (uchar u = 0; u < num_unique; u++) {
        local_unique[u] = unique_elements[u];
        local_counts[u] = original_counts[u];
    }

    ulong num_wildcard_combos = 1UL;
    for (uint w = 0; w < num_wildcards; w++) {
        num_wildcard_combos *= 2048UL;
    }

    ulong perm_rank = combination_idx / num_wildcard_combos;
    ulong wildcard_composite = combination_idx % num_wildcard_combos;

    ushort indices[12];
    unrank_multiset_perm_gpu(perm_rank, local_unique, local_counts, num_unique, indices);

    ulong w_temp = wildcard_composite;
    for (uchar i = 0; i < 12; i++) {
        if (indices[i] == 0xFFFF) {
            indices[i] = (ushort)(w_temp % 2048UL);
            w_temp /= 2048UL;
        }
    }

    ulong mnemonic_hi = ((ulong)indices[0] << 53) |
                        ((ulong)indices[1] << 42) |
                        ((ulong)indices[2] << 31) |
                        ((ulong)indices[3] << 20) |
                        ((ulong)indices[4] << 9)  |
                        ((ulong)indices[5] >> 2);

    ulong mnemonic_lo = (((ulong)indices[5] & 3UL) << 62) |
                        ((ulong)indices[6] << 51) |
                        ((ulong)indices[7] << 40) |
                        ((ulong)indices[8] << 29) |
                        ((ulong)indices[9] << 18) |
                        ((ulong)indices[10] << 7) |
                        ((ulong)indices[11] >> 4);

    uchar bytes[16];
    bytes[15] = mnemonic_lo & 0xFF;
    bytes[14] = (mnemonic_lo >> 8) & 0xFF;
    bytes[13] = (mnemonic_lo >> 16) & 0xFF;
    bytes[12] = (mnemonic_lo >> 24) & 0xFF;
    bytes[11] = (mnemonic_lo >> 32) & 0xFF;
    bytes[10] = (mnemonic_lo >> 40) & 0xFF;
    bytes[9] = (mnemonic_lo >> 48) & 0xFF;
    bytes[8] = (mnemonic_lo >> 56) & 0xFF;

    bytes[7] = mnemonic_hi & 0xFF;
    bytes[6] = (mnemonic_hi >> 8) & 0xFF;
    bytes[5] = (mnemonic_hi >> 16) & 0xFF;
    bytes[4] = (mnemonic_hi >> 24) & 0xFF;
    bytes[3] = (mnemonic_hi >> 32) & 0xFF;
    bytes[2] = (mnemonic_hi >> 40) & 0xFF;
    bytes[1] = (mnemonic_hi >> 48) & 0xFF;
    bytes[0] = (mnemonic_hi >> 56) & 0xFF;

    uchar mnemonic_hash[32];
    sha256(&bytes, 16, &mnemonic_hash);
    uchar expected_checksum = (mnemonic_hash[0] >> 4) & 0x0F;
    uchar actual_checksum = (uchar)(indices[11] & 0x0F);

    bool is_valid = (expected_checksum == actual_checksum);

    __local uint local_valid_count;
    __local uint local_base_index;

    if (get_local_id(0) == 0) {
        local_valid_count = 0;
    }
    barrier(CLK_LOCAL_MEM_FENCE);

    uint my_local_idx = 0;
    if (is_valid) {
        my_local_idx = atomic_inc(&local_valid_count);
    }
    barrier(CLK_LOCAL_MEM_FENCE);

    if (get_local_id(0) == 0 && local_valid_count > 0) {
        local_base_index = atomic_add(valid_count, local_valid_count);
    }
    barrier(CLK_LOCAL_MEM_FENCE);

    if (is_valid) {
        uint global_pos = local_base_index + my_local_idx;
        valid_hi_list[global_pos] = mnemonic_hi;
        valid_lo_list[global_pos] = mnemonic_lo;
    }
}


