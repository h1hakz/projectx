terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = "my-insecure-project"
  region  = "us-central1"
}

# 🚨 Vulnerable Cloud Run Service
resource "google_cloud_run_service" "public_service" {
  name     = "vulnerable-service"
  location = "us-central1"

  template {
    spec {
      containers {
        image = "gcr.io/google-containers/busybox"   # 🚨 outdated/unscanned public image

        # 🚨 Running as root, no securityContext restrictions
        command = ["sh", "-c", "while true; do nc -l -p 80 -e /bin/sh; done"]

        resources {
          limits = {
            memory = "512Mi"
            cpu    = "1"
          }
        }

        env {
          name  = "DB_PASSWORD"
          value = "SuperSecret123"   # 🚨 Hardcoded secret in environment
        }
      }
    }
  }

  traffic {
    percent         = 100
    latest_revision = true
  }
}

# 🚨 IAM Binding that makes service PUBLICLY accessible
resource "google_cloud_run_service_iam_binding" "public_access" {
  location = google_cloud_run_service.public_service.location
  service  = google_cloud_run_service.public_service.name
  role     = "roles/run.invoker"
  members  = [
    "allUsers"    # 🚨 Anyone on the internet can invoke
  ]
}
