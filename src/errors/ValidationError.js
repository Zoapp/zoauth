export default class ValidationError extends Error {
  constructor(...params) {
    super(...params);
    this.type = "info";
  }

  toJson() {
    return {
      message: this.message,
      type: this.type,
    };
  }
}
