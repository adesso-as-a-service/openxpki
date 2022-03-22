'use strict';

module.exports = function (environment) {
  let ENV = {
    modulePrefix: 'openxpki',
    podModulePrefix: 'openxpki/pods',   // namespaced directory where resolver will look for resource files
    environment: environment,
    rootURL: '/openxpki/',  // https://guides.emberjs.com/release/configuring-ember/embedding-applications/#toc_specifying-a-root-url
    locationType: 'hash',   // https://guides.emberjs.com/release/configuring-ember/specifying-url-type/
    EmberENV: {
      FEATURES: {
        // Here you can enable experimental features on an ember canary build
        // e.g. EMBER_NATIVE_DECORATOR_SUPPORT: true
      },
      EXTEND_PROTOTYPES: {
        // Prevent Ember Data from overriding Date.parse.
        Date: false,
      },
    },

    APP: {
      // Here you can pass flags/options to your application instance
      // when it is created
    },
  };

  /*
   * Custom global constants
   */
  ENV.buildYear = new Date().getFullYear();

  /*
   * Mode specific
   */
  if (environment === 'development') {
    /*
     * Set up logging
     * https://guides.emberjs.com/release/configuring-ember/debugging/
     */
    //ENV.APP.LOG_RESOLVER = true;
    //ENV.APP.LOG_ACTIVE_GENERATION = true; // this will log Ember-internal component names, e.g. "template:components/oxi-base/formatted"
    ENV.APP.LOG_TRANSITIONS = true;       // Basic logging, e.g. "Transitioned into 'post'"
    ENV.APP.LOG_TRANSITIONS_INTERNAL = true;  // Detailed logging incl. internal steps made while transitioning into a route
    ENV.APP.LOG_VIEW_LOOKUPS = true;
  }

  if (environment === 'test') {
    // Testem prefers this...
    ENV.locationType = 'none';

    // keep test console output quieter
    ENV.APP.LOG_ACTIVE_GENERATION = false;
    ENV.APP.LOG_VIEW_LOOKUPS = false;

    ENV.APP.rootElement = '#ember-testing';
    ENV.APP.autoboot = false;
  }

  if (environment === 'production') {
    // here you can enable a production-specific feature
  }

  return ENV;
};
