var bcrypt = require('../bcrypt');

module.exports = {
    test_salt_length: function(assert) {
        var salt = bcrypt.genSaltSync(10);
        assert.equals(29, salt.length, "Salt isn't the correct length.");
        var split_salt = salt.split('$');
        assert.ok(split_salt[1], '2a');
        assert.ok(split_salt[2], '10');
        assert.done();
    },
    test_salt_no_params: function(assert) {
        // same as test_verify_salt except using default rounds of 10
        var salt = bcrypt.genSaltSync();
        var split_salt = salt.split('$');
        assert.ok(split_salt[1], '2a');
        assert.ok(split_salt[2], '10');
        assert.done();
    },
    test_salt_rounds_is_string_number: function(assert) {
        assert.throws(function() {bcrypt.genSaltSync('10');}, "Should throw an Error. No params.");
        assert.done();
    },
    test_salt_rounds_is_NaN: function(assert) {
        assert.throws(function() {bcrypt.genSaltSync('b');}, "Should throw an Error. gen_salt requires rounds to be a number.");
        assert.done();
    },
    test_hash: function(assert) {
        assert.ok(bcrypt.hashSync(new Buffer('password'), bcrypt.genSaltSync(10)), "Shouldn't throw an Error.");
        assert.done();
    },
    test_hash_rounds: function(assert) {
        var hash = bcrypt.hashSync(new Buffer('password'), 8);
        assert.equals(bcrypt.getRounds(hash), 8, "Number of rounds should equal 8.");
        assert.done();
    },
    test_hash_empty_string: function(assert) {
        assert.ok(bcrypt.hashSync(new Buffer(''), bcrypt.genSaltSync(10)), "Shouldn't throw an Error.");
        assert.throws(function() {bcrypt.hashSync(new Buffer('password'), '')}, "Should have thrown an Error related to the salt.");
        assert.throws(function() {bcrypt.hashSync(new Buffer(''), '')}, "Should have thrown an Error related to the salt.");
        assert.done();
    },
    test_hash_pw_no_params: function(assert) {
        assert.throws(function() {bcrypt.hashSync();}, "Should throw an Error. No Params.");
        assert.done();
    },
    test_hash_pw_one_param: function(assert) {
        assert.throws(function() {bcrypt.hashSync(new Buffer('password'));}, "Should throw an Error. No salt.");
        assert.done();
    },
    test_hash_pw_not_hash_str: function(assert) {
        assert.throws(function() {bcrypt.hashSync(new Buffer('password'), {});}, "Should throw an Error. hash should be a string or number.");
        assert.done();
    },
    test_hash_salt_validity: function(assert) {
        assert.expect(2);
        assert.ok(bcrypt.hashSync(new Buffer('password'), '$2a$10$somesaltyvaluertsetrse'));
        assert.throws(function() {
            bcrypt.hashSync(new Buffer('password'), 'some$value');
        });
        assert.done();
    },
    test_verify_salt: function(assert) {
        var salt = bcrypt.genSaltSync(10);
        var split_salt = salt.split('$');
        assert.ok(split_salt[1], '2a');
        assert.ok(split_salt[2], '10');
        assert.done();
    },
    test_verify_salt_min_rounds: function(assert) {
        var salt = bcrypt.genSaltSync(1);
        var split_salt = salt.split('$');
        assert.ok(split_salt[1], '2a');
        assert.ok(split_salt[2], '4');
        assert.done();
    },
    test_verify_salt_max_rounds: function(assert) {
        var salt = bcrypt.genSaltSync(100);
        var split_salt = salt.split('$');
        assert.ok(split_salt[1], '2a');
        assert.ok(split_salt[2], '31');
        assert.done();
    },
    test_hash_compare: function(assert) {
        var salt = bcrypt.genSaltSync(10);
        assert.equals(29, salt.length, "Salt isn't the correct length.");
        var hash = bcrypt.hashSync(new Buffer("test"), salt);
        assert.ok(bcrypt.compareSync(new Buffer("test"), hash), "These hashes should be equal.");
        assert.ok(!(bcrypt.compareSync(new Buffer("blah"), hash)), "These hashes should not be equal.");
        assert.done();
    },
    test_hash_compare_empty_strings: function(assert) {
        assert.ok(!(bcrypt.compareSync(new Buffer(""), "password")), "These hashes should not be equal.");
        assert.ok(!(bcrypt.compareSync(new Buffer(""), "")), "These hashes should not be equal.");
        assert.ok(!(bcrypt.compareSync(new Buffer("password"), "")), "These hashes should not be equal.");
        assert.done();
    },
    test_hash_compare_invalid_strings: function(assert) {
      var fullString = new Buffer('envy1362987212538');
      var hash = '$2a$10$XOPbrlUPQdwdJUpSrIF6X.LbE14qsMmKGhM1A8W9iqaG3vv1BD7WC';
      var wut = ':';
      bcrypt.compareSync(fullString, hash, function(err, res) {
        assert.ok(res);
      });
      bcrypt.compareSync(fullString, wut, function(err, res) {
        assert.ok(!res)
      });
      assert.done();
    },
    test_getRounds: function(assert) {
        var hash = bcrypt.hashSync(new Buffer("test"), bcrypt.genSaltSync(9));
        assert.equals(9, bcrypt.getRounds(hash), "getRounds can't extract rounds");
        assert.done();
    },
    test_getRounds: function(assert) {
        var hash = bcrypt.hashSync(new Buffer("test"), bcrypt.genSaltSync(9));
        assert.equals(9, bcrypt.getRounds(hash), "getRounds can't extract rounds");
        assert.throws(function() {bcrypt.getRounds(''); }, "Must pass a valid hash to getRounds");
        assert.done();
    }
};
