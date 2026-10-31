/* Cosmonic consent-gated analytics for this demo page.
   Same logic as cosmonic.com/site.js: Consent Mode v2 defaults to denied,
   the HubSpot tracker loads first (it draws the cookie banner and arbitrates
   consent), and Google Tag Manager and Apollo load only once the visitor's
   consent allows them. A footer "Cookie Preferences" button, if present as
   #cookie-prefs-item / #cookie-prefs, is revealed when a banner applies. */
(function () {
  var _hsp = (window._hsp = window._hsp || []);
  window.dataLayer = window.dataLayer || [];
  function gtag() {
    dataLayer.push(arguments);
  }

  gtag('set', 'developer_id.dZTQ1Zm', true);
  gtag('consent', 'default', {
    ad_storage: 'denied',
    analytics_storage: 'denied',
    ad_user_data: 'denied',
    ad_personalization: 'denied',
    wait_for_update: 1000,
  });

  function loadGtm() {
    if (window._hsGtmLoadOnce) {
      return;
    }
    _hsp.push(['useGoogleConsentModeV2']);
    window.dataLayer.push({'gtm.start': new Date().getTime(), 'event': 'gtm.js'});
    var s = document.createElement('script');
    s.src = 'https://www.googletagmanager.com/gtm.js?id=GTM-57XRGHW';
    s.async = true;
    document.head.appendChild(s);
    window._hsGtmLoadOnce = true;
  }

  function loadApollo() {
    if (window._cosmonicApolloLoadOnce) {
      return;
    }
    window._cosmonicApolloLoadOnce = true;
    var n = Math.random().toString(36).substring(7);
    var o = document.createElement('script');
    o.src = 'https://assets.apollo.io/micro/website-tracker/tracker.iife.js?nocache=' + n;
    o.async = true;
    o.defer = true;
    o.onload = function () {
      window.trackingFunctions.onLoad({appId: '6a28f435290ea7000c73f26e'});
    };
    document.head.appendChild(o);
  }

  _hsp.push([
    'addPrivacyConsentListener',
    function (consent) {
      var c = consent.categories || {};
      if (consent.allowed || c.analytics) {
        loadGtm();
      }
      if (consent.allowed || c.advertisement) {
        loadApollo();
      }
    },
  ]);

  _hsp.push([
    'addPrivacySettingsListener',
    function () {
      revealPrefs();
    },
  ]);

  function revealPrefs() {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', revealPrefs, {once: true});
      return;
    }
    var item = document.getElementById('cookie-prefs-item');
    if (!item || !item.hidden) {
      return;
    }
    item.hidden = false;
    document.getElementById('cookie-prefs').addEventListener('click', function () {
      _hsp.push(['showBanner']);
    });
  }

  var hubSpotLoaded = false;
  var WAKE = ['pointerdown', 'keydown', 'touchstart', 'scroll', 'mousemove'];
  function loadHubSpot() {
    if (hubSpotLoaded) {
      return;
    }
    hubSpotLoaded = true;
    WAKE.forEach(function (e) {
      removeEventListener(e, loadHubSpot, {passive: true});
    });
    var s = document.createElement('script');
    s.id = 'hs-script-loader';
    s.src = 'https://js.hs-scripts.com/20760433.js';
    s.async = true;
    s.defer = true;
    document.head.appendChild(s);
  }
  WAKE.forEach(function (e) {
    addEventListener(e, loadHubSpot, {passive: true});
  });
  function afterLoad() {
    setTimeout(loadHubSpot, 3000);
  }
  if (document.readyState === 'complete') {
    afterLoad();
  } else {
    addEventListener('load', afterLoad, {once: true});
  }
})();
