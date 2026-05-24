-- Canonical destination offices.

INSERT INTO offices (office_name) VALUES
  ('PMED'),
  ('PRDP'),
  ('RSBSA'),
  ('RAED'),
  ('Research Office'),
  ('Finance Accounting'),
  ('Admin Department'),
  ('Regional Executive Director'),
  ('Records'),
  ('Operations')
ON DUPLICATE KEY UPDATE office_name = VALUES(office_name);
