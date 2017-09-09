const Joi = require('joi');

const incidents = require('../services/incidents');

module.exports = [
  {
    method: 'POST',
    path: '/incidents',
    handler: async (req, reply) => {
      // TODO: get userId from the token
      // req.auth.credentials.id
      const userId = 1; // hardcoded for now
      const [ added ] = await incidents.createIncident(req.payload, userId);
      console.log(added);
      reply({ id: added });
    },
    config: {
      validate: {
        payload: {
          description: Joi.string().required(),
          category_id: Joi.number().required(),
          date_occurred: Joi.date().required(),
        },
      },
    },
  },
];
