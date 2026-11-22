//! Le tableau de bord du Connecteur sert aussi celui du Nœud administré à
//! distance : les deux copies doivent rester identiques.

#[test]
fn node_and_connector_dashboards_are_identical() {
    for f in ["app.js", "index.html"] {
        let mine = std::fs::read(format!("dashboard/{f}")).unwrap();
        let node = std::fs::read(format!("../node/dashboard/{f}")).unwrap();
        assert!(
            mine == node,
            "dashboard/{f} diffère de celui du Nœud : recopiez-le"
        );
    }
}
